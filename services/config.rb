coreo_aws_advisor_alert "rds-inventory" do
  action :define
  service :rds
  # link "http://kb.cloudcoreo.com/mydoc_ec2-inventory.html"
  include_violations_in_count false
  display_name "RDS Instance Inventory"
  description "This rule performs an inventory on all RDS DB instances in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["db_instances"]
  audit_objects ["object.db_instances.db_instance_identifier"]
  operators ["=~"]
  alert_when [//]
  id_map "object.db_instances.db_instance_identifier"
end

coreo_aws_advisor_alert "rds-short-backup-retention-period" do
  action :define
  service :rds
  link "http://kb.cloudcoreo.com/mydoc_rds-short-backup-retention-period.html"
  display_name "RDS short backup retention period"
  description "The affected RDS database has a short backup retention period (less than 30 days)."
  category "Dataloss"
  suggested_action "Modify the backup retension period to increase it to greater than 30 days."
  level "Warning"
  objectives ["db_instances"]
  audit_objects ["db_instances.backup_retention_period"]
  operators ["<"]
  alert_when [30]
  id_map "object.db_instances.db_instance_identifier"
end

coreo_aws_advisor_alert "rds-no-auto-minor-version-upgrade" do
  action :define
  service :rds
  link "http://kb.cloudcoreo.com/mydoc_rds-no-auto-minor-version-upgrade.html"
  display_name "RDS not set to automatically upgrade"
  description "RDS is not set to automatically upgrade minor versions on your database instance."
  category "Reliability"
  suggested_action "Consider whether you would like AWS to automatically upgrade minor versions on your database instance. Modify your settings to allow minor version upgrades if possible."
  level "Critical"
  objectives ["db_instances"]
  audit_objects ["db_instances.auto_minor_version_upgrade"]
  operators ["=="]
  alert_when [false]
  id_map "object.db_instances.db_instance_identifier"
end

coreo_aws_advisor_alert "rds-db-publicly-accessible" do
  action :define
  service :rds
  link "http://kb.cloudcoreo.com/mydoc_rds-db-publicly-accessible.html"
  display_name "RDS is publicly accessible to the world"
  description "The affected RDS database is publicly accessible to the world."
  category "Security"
  suggested_action "Consider whether the affected RDS database should be publicly accessible to the world. If not, modify the option which enables your RDS database to become publicly accessible."
  level "Critical"
  objectives ["db_instances"]
  audit_objects ["db_instances.publicly_accessible"]
  operators ["=="]
  alert_when [true]
  id_map "object.db_instances.db_instance_identifier"
end

coreo_aws_advisor_rds "advise-rds" do
  alerts ${AUDIT_AWS_RDS_ALERT_LIST}
  action :advise
  regions ${AUDIT_AWS_RDS_REGIONS}
end

coreo_uni_util_jsrunner "rds-aggregate" do
  action :run
  json_input '{"composite name":"PLAN::stack_name",
  "plan name":"PLAN::name",
  "number_of_checks":"COMPOSITE::coreo_aws_advisor_rds.advise-rds.number_checks",
  "number_of_violations":"COMPOSITE::coreo_aws_advisor_rds.advise-rds.number_violations",
  "number_violations_ignored":"COMPOSITE::coreo_aws_advisor_rds.advise-rds.number_ignored_violations",
  "violations":COMPOSITE::coreo_aws_advisor_rds.advise-rds.report}'
  function <<-EOH

var_regions = "${AUDIT_AWS_RDS_REGIONS}";

var result = {};
result['composite name'] = json_input['composite name'];
result['plan name'] = json_input['plan name'];
result['number_of_checks'] = json_input['number_of_checks'];
result['number_of_violations'] = json_input['number_of_violations'];
result['number_violations_ignored'] = json_input['number_violations_ignored'];
result['regions'] = var_regions;
result['violations'] = json_input['violations'];

callback(result);
  EOH
end

coreo_uni_util_jsrunner "jsrunner-process-suppressions" do
  action :run
  provide_composite_access true
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.rds-aggregate.return'
  packages([
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  function <<-EOH
    var fs = require('fs');
    var yaml = require('js-yaml');

// Get document, or throw exception on error
    try {
        var suppressions = yaml.safeLoad(fs.readFileSync('./suppressions.yaml', 'utf8'));
        console.log(suppressions);
    } catch (e) {
        console.log(e);
    }

    var result = {};
    result["composite name"] = json_input["composite name"];
    result["number_of_violations"] = json_input["number_of_violations"];
    result["plan name"] = json_input["plan name"];
    result["regions"] = json_input["regions"];
    result["violations"] = {};

    for (var violator_id in json_input.violations) {
        result["violations"][violator_id] = {};
        result["violations"][violator_id].tags = json_input.violations[violator_id].tags;
        result["violations"][violator_id].violations = {}
        //console.log(violator_id);
        for (var rule_id in json_input.violations[violator_id].violations) {
            console.log("object " + violator_id + " violates rule " + rule_id);
            is_violation = true;
            for (var suppress_rule_id in suppressions["suppressions"]) {
                for (var suppress_violator_id in suppressions["suppressions"][suppress_rule_id]) {
                    var suppress_obj_id = suppressions["suppressions"][suppress_rule_id][suppress_violator_id];
                    console.log(" compare: " + rule_id + ":" + violator_id + " <> " + suppress_rule_id + ":" + suppress_obj_id);
                    if (rule_id === suppress_rule_id) {
                        console.log("    have a suppression for rule: " + rule_id);
                        if (violator_id === suppress_obj_id) {
                            console.log("    *** found violation to suppress: " + suppress_obj_id);
                            is_violation = false;
                        }
                    }
                }
            }
            if (is_violation) {
                console.log("    +++ not suppressed - including in results");
                result["violations"][violator_id].violations[rule_id] = json_input.violations[violator_id].violations[rule_id];
            }
        }
    }

    var rtn = result;

    callback(result);


EOH
end

# coreo_uni_util_jsrunner "jsrunner-output-table" do
#   action :notify
#   provide_composite_access true
#   json_input 'COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-suppressions.return'
#   packages([
#                {
#                    :name => "js-yaml",
#                    :version => "3.7.0"
#                }       ])
#   function <<-EOH
#
#     Object.byString = function(o, s) {
#     s = s.replace(/\\[(w+)\\]/g, '.$1'); // convert indexes to properties
#     s = s.replace(/^\\./, '');           // strip a leading dot
#     var a = s.split('.');
#     for (var i = 0, n = a.length; i < n; ++i) {
#         var k = a[i];
#         if (k in o) {
#             o = o[k];
#         } else {
#             return;
#         }
#     }
#     return o;
#     }
#
#     var fs = require('fs');
#     var yaml = require('js-yaml');
#
# // Get document, or throw exception on error
#     try {
#         var tables = yaml.safeLoad(fs.readFileSync('./tables.yaml', 'utf8'));
#         console.log(tables);
#     } catch (e) {
#         console.log(e);
#     }
#
#     var result = {};
#
#     for (var violator_id in json_input.violations) {
#         for (var rule_id in json_input.violations[violator_id].violations) {
#             console.log("object " + violator_id + " violates rule " + rule_id);
#             if (result[rule_id]) {
#             } else {
#                 result[rule_id] = {};
#                 result[rule_id]["header"] = "";
#                 result[rule_id]["nrows"] = 0;
#                 result[rule_id]["rows"] = {};
#             }
#             for (var table_rule_id in tables) {
#                 //console.log(table_rule_id);
#                 if (rule_id === table_rule_id) {
#                     //console.log("found a table entry for rule: " + rule_id);
#                     var col_num = 0;
#                     var col_num_str = col_num.toString();
#                     var this_row = "";
#                     for (var table_entry in tables[table_rule_id]) {
#                         console.log("  " + table_entry + " is " + tables[table_rule_id][table_entry]);
#                         var indx = result[rule_id]["header"].indexOf(table_entry);
#                         if (result[rule_id]["header"].indexOf(table_entry) === -1) {
#                             result[rule_id]["header"] = result[rule_id]["header"] + "," + table_entry;
#                         }
#                         var resolved_entry = tables[table_rule_id][table_entry];
#                         var re = /__OBJECT__/gi;
#                         resolved_entry = resolved_entry.replace(re, violator_id);
#                         re = /__RULE__/gi;
#                         resolved_entry = resolved_entry.replace(re, rule_id);
#
#                         var tags = null;
#                         tags = json_input.violations[violator_id].tags;
#
#                         re = /\\+([^+]+)\\+/;
#                         var match;
#                         while (match = re.exec(resolved_entry)) {
#                             console.log(match);
#                             var to_resolve = match[1];
#                             var resolved = Object.byString(json_input.violations, to_resolve);
#                             if (resolved && resolved.match(/arn:aws/)) {
#                                 resolved = resolved.replace("/", "@");
#                             }
#                             resolved_entry = resolved_entry.replace(match[0], resolved);
#
#                         }
#                         if (!result[rule_id]["rows"][col_num]) {
#                             result[rule_id]["rows"][col_num] = {};
#                         }
#                         this_row = this_row + "," + resolved_entry;
#
#                         col_num++;
#                         col_num_str = col_num.toString();
#
#                     }
#                     result[rule_id]["header"] = result[rule_id]["header"].replace(/^,/, "");
#
#                     var row_num = result[rule_id]["nrows"];
#                     var row_num_str = row_num.toString();
#
#
#                     this_row = this_row.replace(/^,/, "");
#                     result[rule_id]["rows"][row_num_str] = this_row;
#
#                     result[rule_id]["nrows"]++;
#                 }
#             }
#         }
#     }
#
#     var rtn = result;
#
#     callback(result);
#
#
# EOH
# end

# coreo_uni_util_variables "update-advisor-output" do
#   action :set
#   variables([
#        {'COMPOSITE::coreo_aws_advisor_rds.advise-rds.report' => 'COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-suppressions.return.violations'}
#       ])
# end

=begin
  START AWS RDS METHODS
  JSON SEND METHOD
  HTML SEND METHOD
=end
coreo_uni_util_notify "advise-rds-json" do
  action :nothing
  type 'email'
  allow_empty ${AUDIT_AWS_RDS_ALLOW_EMPTY}
  send_on '${AUDIT_AWS_RDS_SEND_ON}'
  payload '{"composite name":"PLAN::stack_name",
  "plan name":"PLAN::name",
  "number_of_checks":"COMPOSITE::coreo_aws_advisor_rds.advise-rds.number_checks",
  "number_of_violations":"COMPOSITE::coreo_aws_advisor_rds.advise-rds.number_violations",
  "number_violations_ignored":"COMPOSITE::coreo_aws_advisor_rds.advise-rds.number_ignored_violations",
  "violations": COMPOSITE::coreo_aws_advisor_rds.advise-rds.report }'
  payload_type "json"
  endpoint ({
      :to => '${AUDIT_AWS_RDS_ALERT_RECIPIENT}', :subject => 'CloudCoreo rds advisor alerts on PLAN::stack_name :: PLAN::name'
  })
end

coreo_uni_util_jsrunner "tags-to-notifiers-array-rds" do
  action :run
  data_type "json"
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.4.8"
               },
               {
                   :name => "fs"
               },
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               } ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "violations": COMPOSITE::coreo_aws_advisor_rds.advise-rds.report}'
  function <<-EOH

const tables = {
    "rds-short-backup-retention-period": {
        "AWS Region": "+__OBJECT__.violations.__RULE__.region+~https://+__OBJECT__.violations.__RULE__.region+.console.aws.amazon.com/cloudtrail/home?region=+__OBJECT__.violations.__RULE__.region+",
        "AWS Tags": "+__OBJECT__.tags+",
        "Trail Name": "+__OBJECT__+~https://+__OBJECT__.violations.__RULE__.region+.console.aws.amazon.com/cloudtrail/home?region=+__OBJECT__.violations.__RULE__.region+#/configuration/+__OBJECT__.violations.__RULE__.violating_object.0.object.trail_arn+"
    },
    "rds-no-auto-minor-version-upgrade": {
        "AWS Region": "+__OBJECT__.violations.__RULE__.region+~https://+__OBJECT__.violations.__RULE__.region+.console.aws.amazon.com/cloudtrail/home?region=+__OBJECT__.violations.__RULE__.category+",
        "AWS Tags": "+__OBJECT__.tags+"
    },
    "rds-db-publicly-accessible": {
        "AWS Region": "+__OBJECT__.violations.__RULE__.region+~https://+__OBJECT__.violations.__RULE__.region+.console.aws.amazon.com/cloudtrail/home?region=+__OBJECT__.violations.__RULE__.region+",
        "AWS Tags": "+__OBJECT__.tags+"
    },
    "rds-inventory": {
        "AWS Region": "+__OBJECT__.violations.__RULE__.region+~https://+__OBJECT__.violations.__RULE__.region+.console.aws.amazon.com/cloudtrail/home?region=+__OBJECT__.violations.__RULE__.category+",
        "AWS Tags": "+__OBJECT__.tags+"
    }
};



const JSON_INPUT = json_input;
const NO_OWNER_EMAIL = "${AUDIT_AWS_RDS_ALERT_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_RDS_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_RDS_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_RDS_SEND_ON}";
const AUDIT_NAME = 'rds';
const TABLES = tables;
const SHOWN_NOT_SORTED_VIOLATIONS_COUNTER = false;

const sortFuncForViolationAuditPanel = function sortViolationFunc(JSON_INPUT) {
    let violations = JSON_INPUT.violations;
    let counterForViolations = 0;
    let counterForSortedViolations = 0;
    if (violations.hasOwnProperty('violations')) {
        violations = JSON_INPUT.violations.violations;
    }
    const violationKeys = Object.keys(violations);
    violationKeys.forEach(violationKey => {
        const alertKeys = Object.keys(violations[violationKey].violations);
        alertKeys.forEach(alertKey => {
            if (violations[violationKey].violations[alertKey].region === 'us-east-1') {
                delete violations[violationKey].violations[alertKey];
                counterForSortedViolations--;
                if (Object.keys(violations[violationKey].violations).length === 0) {
                    delete violations[violationKey];
                }
            }
            counterForViolations++;
            counterForSortedViolations++;
        });
    });

    JSON_INPUT['counterForViolations'] = counterForViolations.toString();
    JSON_INPUT['counterForSortedViolations'] = counterForSortedViolations.toString();
    return JSON_INPUT;
};
const sortFuncForHTMLReport = function htmlSortFunc(JSON_INPUT) {
    let violations = JSON_INPUT.violations;
    let counterForViolations = 0;
    let counterForSortedViolations = 0;
    if (violations.hasOwnProperty('violations')) {
        violations = JSON_INPUT.violations.violations;
    }
    const violationKeys = Object.keys(violations);
    violationKeys.forEach(violationKey => {
        const alertKeys = Object.keys(violations[violationKey].violations);
        alertKeys.forEach(alertKey => {
            if (violations[violationKey].violations[alertKey].region == 'us-east-1') {
                delete violations[violationKey].violations[alertKey];
                if (Object.keys(violations[violationKey].violations).length === 0) {
                    delete violations[violationKey];
                }
                counterForSortedViolations--;
            }
            counterForViolations++;
            counterForSortedViolations++;
        });
    });
    JSON_INPUT['counterForViolations'] = counterForViolations;
    JSON_INPUT['counterForSortedViolations'] = counterForSortedViolations;
    return JSON_INPUT;
};

const WHAT_NEED_TO_SHOWN_ON_TABLE = {
    OBJECT_ID: { headerName: 'AWS Object ID', isShown: true},
    REGION: { headerName: 'Region', isShown: true },
    AWS_CONSOLE: { headerName: 'AWS Console', isShown: true },
    TAGS: { headerName: 'Tags', isShown: true },
    AMI: { headerName: 'AMI', isShown: false },
    KILL_SCRIPTS: { headerName: 'Kill Cmd', isShown: false }
};

const VARIABLES = { NO_OWNER_EMAIL, OWNER_TAG, AUDIT_NAME,
    WHAT_NEED_TO_SHOWN_ON_TABLE, ALLOW_EMPTY, SEND_ON,
    undefined, undefined, SHOWN_NOT_SORTED_VIOLATIONS_COUNTER};

const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditRDS = new CloudCoreoJSRunner(JSON_INPUT, VARIABLES, TABLES);
const notifiers = AuditRDS.getNotifiers();
callback(notifiers);
  EOH
end

coreo_uni_util_jsrunner "tags-rollup-rds" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-rds.return'
  function <<-EOH
var rollup_string = "";
let rollup = '';
let emailText = '';
let numberOfViolations = 0;
for (var entry=0; entry < json_input.length; entry++) {
    if (json_input[entry]['endpoint']['to'].length) {
        numberOfViolations += parseInt(json_input[entry]['num_violations']);
        emailText += "recipient: " + json_input[entry]['endpoint']['to'] + " - " + "nViolations: " + json_input[entry]['num_violations'] + "\\n";
    }
}

rollup += 'number of Violations: ' + numberOfViolations + "\\n";
rollup += 'Rollup' + "\\n";
rollup += emailText;

rollup_string = rollup;
callback(rollup_string);
  EOH
end

coreo_uni_util_notify "advise-rds-to-tag-values" do
  action :${AUDIT_AWS_RDS_HTML_REPORT}
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-rds.return'
end

coreo_uni_util_notify "advise-rds-rollup" do
  action :${AUDIT_AWS_RDS_ROLLUP_REPORT}
  type 'email'
  allow_empty ${AUDIT_AWS_RDS_ALLOW_EMPTY}
  send_on '${AUDIT_AWS_RDS_SEND_ON}'
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
COMPOSITE::coreo_uni_util_jsrunner.tags-rollup-rds.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_RDS_ALERT_RECIPIENT}', :subject => 'CloudCoreo rds advisor alerts on PLAN::stack_name :: PLAN::name'
  })
end
=begin
  AWS RDS END
=end
