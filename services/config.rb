
# section 1: user-visible engine-powered rule definitions

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

# section 2: user-visible jsrunner-powered rule definitions

# section 3: internal-use engine-powered rule definitions

# section 4: cross-resource variable holder

coreo_uni_util_variables "planwide" do
  action :set
  variables([
       {'COMPOSITE::coreo_uni_util_variables.planwide.initialized' => true}
      ])
end

# section 5: primary service advisor

coreo_aws_advisor_rds "advise-rds" do
  alerts ${AUDIT_AWS_RDS_ALERT_LIST}
  action :advise
  regions ${AUDIT_AWS_RDS_REGIONS}
end

coreo_uni_util_variables "planwide" do
  action :set
  variables([
       {'COMPOSITE::coreo_uni_util_variables.planwide.results' => 'COMPOSITE::coreo_aws_advisor_rds.advise-rds.report'},
       {'COMPOSITE::coreo_uni_util_variables.planwide.number_violations' => 'COMPOSITE::coreo_aws_advisor_rds.advise-rds.number_violations'},
       {'COMPOSITE::coreo_uni_util_variables.planwide.composite_name' => 'PLAN::stack_name'},
       {'COMPOSITE::coreo_uni_util_variables.planwide.plan_name' => 'PLAN::name'}
      ])
end

coreo_uni_util_jsrunner "jsrunner-process-suppressions" do
  action :run
  provide_composite_access true
  json_input 'COMPOSITE::coreo_uni_util_variables.planwide.results'
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
        var suppressions = yaml.safeLoad(fs.readFileSync('./suppression.yaml', 'utf8'));
        console.log(suppressions);
    } catch (e) {
        console.log(e);
    }

    var result = {};
    var file_date = null;
    for (var violator_id in json_input) {
        result[violator_id] = {};
        result[violator_id].tags = json_input[violator_id].tags;
        result[violator_id].violations = {}
        //console.log(violator_id);
        for (var rule_id in json_input[violator_id].violations) {
            console.log("object " + violator_id + " violates rule " + rule_id);
            is_violation = true;

            result[violator_id].violations[rule_id] = json_input[violator_id].violations[rule_id];
            for (var suppress_rule_id in suppressions) {
                for (var suppress_violator_num in suppressions[suppress_rule_id]) {
                    for (var suppress_violator_id in suppressions[suppress_rule_id][suppress_violator_num]) {
                        file_date = null;
                        var suppress_obj_id_time = suppressions[suppress_rule_id][suppress_violator_num][suppress_violator_id];
                        console.log(" compare: " + rule_id + ":" + violator_id + " <> " + suppress_rule_id + ":" + suppress_violator_id);
                        if (rule_id === suppress_rule_id) {
                            console.log("    have a suppression for rule: " + rule_id);

                            if (violator_id === suppress_violator_id) {
                                var now_date = new Date();

                                if (suppress_obj_id_time === "") {
                                    suppress_obj_id_time = new Date();
                                } else {
                                    file_date = suppress_obj_id_time;
                                    suppress_obj_id_time = file_date;
                                }
                                var rule_date = new Date(suppress_obj_id_time);
                                if (isNaN(rule_date.getTime())) {
                                    console.log("invalid date, setting expiration to time zero");
                                    rule_date = new Date(0);
                                }

                                if (now_date <= rule_date) {

                                    console.log("    *** found violation to suppress: " + violator_id);
                                    is_violation = false;

                                    result[violator_id].violations[rule_id]["suppressed"] = true;
                                    if (file_date != null) {
                                        result[violator_id].violations[rule_id]["suppressed_until"] = file_date;
                                        result[violator_id].violations[rule_id]["suppression_expired"] = false;
                                    }
                                }
                            }
                        }
                    }

                }
            }
            if (is_violation) {
                console.log("    +++ not suppressed");

                if (file_date !== null) {
                    result[violator_id].violations[rule_id]["suppressed_until"] = file_date;
                    result[violator_id].violations[rule_id]["suppression_expired"] = true;
                } else {
                    result[violator_id].violations[rule_id]["suppression_expired"] = false;
                }
                result[violator_id].violations[rule_id]["suppressed"] = false;
            }
        }
    }

    var rtn = result;

    callback(result);


EOH
end

coreo_uni_util_variables "add-suppressions-to-results" do
  action :set
  variables([
       {'COMPOSITE::coreo_uni_util_variables.planwide.results' => 'COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-suppressions.return'}
      ])
end

coreo_uni_util_jsrunner "jsrunner-output-table" do
  action :run
  provide_composite_access true
  json_input 'COMPOSITE::coreo_uni_util_variables.planwide.results'
  packages([
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  function <<-EOH

    Object.byString = function(o, s) {
    s = s.replace(/\\[(w+)\\]/g, '.$1'); // convert indexes to properties
    s = s.replace(/^\\./, '');           // strip a leading dot
    var a = s.split('.');
    for (var i = 0, n = a.length; i < n; ++i) {
        var k = a[i];
        if (k in o) {
            o = o[k];
        } else {
            return;
        }
    }
    return o;
    }

    var fs = require('fs');
    var yaml = require('js-yaml');

// Get document, or throw exception on error
    try {
        var tables = yaml.safeLoad(fs.readFileSync('./table.yaml', 'utf8'));
        console.log(tables);
    } catch (e) {
        console.log(e);
    }

    var result = {};

    for (var violator_id in json_input) {
        for (var rule_id in json_input[violator_id].violations) {
            console.log("object " + violator_id + " violates rule " + rule_id);
            if (result[rule_id]) {
            } else {
                result[rule_id] = {};
                result[rule_id]["header"] = "";
                result[rule_id]["nrows"] = 0;
                result[rule_id]["rows"] = {};
            }
            for (var table_rule_id in tables) {
                //console.log(table_rule_id);
                if (rule_id === table_rule_id) {
                    //console.log("found a table entry for rule: " + rule_id);
                    var col_num = 0;
                    var col_num_str = col_num.toString();
                    var this_row = "";
                    for (var table_entry in tables[table_rule_id]) {
                        console.log("  " + table_entry + " is " + tables[table_rule_id][table_entry]);
                        var indx = result[rule_id]["header"].indexOf(table_entry);
                        if (result[rule_id]["header"].indexOf(table_entry) === -1) {
                            result[rule_id]["header"] = result[rule_id]["header"] + "," + table_entry;
                        }
                        var resolved_entry = tables[table_rule_id][table_entry];
                        var re = /__OBJECT__/gi;
                        resolved_entry = resolved_entry.replace(re, violator_id);
                        re = /__RULE__/gi;
                        resolved_entry = resolved_entry.replace(re, rule_id);

                        var tags = null;
                        tags = json_input[violator_id].tags;
                        var tags_str = "";
                        var tags_key_str = "";
                        for (tag in tags) {
                            var this_tag = tags[tag];
                            var key = this_tag["key"];
                            var value = this_tag["value"];
                            tags_str = tags_str + " " + key + "=" + value;
                            tags_key_str = tags_key_str + " " + key;
                        }
                        tags_str = tags_str.replace(/^ /, "");
                        tags_key_str = tags_key_str.replace(/^ /, "");

                        re = /__TAGS__/gi;
                        resolved_entry = resolved_entry.replace(re, tags_str);
                        re = /__TAGKEYS__/gi;
                        resolved_entry = resolved_entry.replace(re, tags_key_str);

                        re = /\\+([^+]+)\\+/;
                        var match;
                        while (match = re.exec(resolved_entry)) {
                            console.log(match);
                            var to_resolve = match[1];
                            var resolved = Object.byString(json_input, to_resolve);
                            if (resolved && resolved.match(/arn:aws/)) {
                                resolved = resolved.replace("/", "@");
                            }
                            resolved_entry = resolved_entry.replace(match[0], resolved);

                        }

                        this_row = this_row + "," + resolved_entry;

                        col_num++;
                        col_num_str = col_num.toString();

                    }
                    result[rule_id]["header"] = result[rule_id]["header"].replace(/^,/, "");

                    var row_num = result[rule_id]["nrows"];
                    var row_num_str = row_num.toString();

                    if (!result[rule_id]["rows"][row_num_str]) {
                        result[rule_id]["rows"][row_num_str] = {};
                    }

                    this_row = this_row.replace(/^,/, "");
                    result[rule_id]["rows"][row_num_str] = this_row;

                    result[rule_id]["nrows"]++;
                }
            }
        }
    }


    var rtn = result;

    callback(result);


EOH
end

coreo_uni_util_variables "add-display-tables" do
  action :set
  variables([
       {'COMPOSITE::coreo_uni_util_variables.planwide.display' => 'COMPOSITE::coreo_uni_util_jsrunner.jsrunner-output-table.return'}
      ])
end

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
  "violations": COMPOSITE::coreo_uni_util_variables.planwide.results }'
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
                   :version => "1.3.9"
               }       ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "violations": COMPOSITE::coreo_uni_util_variables.planwide.results}'
  function <<-EOH
  
const JSON = json_input;
const NO_OWNER_EMAIL = "${AUDIT_AWS_RDS_ALERT_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_RDS_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_RDS_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_RDS_SEND_ON}";
const AUDIT_NAME = 'rds';

const ARE_KILL_SCRIPTS_SHOWN = false;
const EC2_LOGIC = ''; // you can choose 'and' or 'or';
const EXPECTED_TAGS = ['example_2', 'example_1'];

const WHAT_NEED_TO_SHOWN = {
    OBJECT_ID: {
        headerName: 'AWS Object ID',
        isShown: true,
    },
    REGION: {
        headerName: 'Region',
        isShown: true,
    },
    AWS_CONSOLE: {
        headerName: 'AWS Console',
        isShown: true,
    },
    TAGS: {
        headerName: 'Tags',
        isShown: true,
    },
    AMI: {
        headerName: 'AMI',
        isShown: false,
    },
    KILL_SCRIPTS: {
        headerName: 'Kill Cmd',
        isShown: false,
    }
};

const VARIABLES = {
    NO_OWNER_EMAIL,
    OWNER_TAG,
    AUDIT_NAME,
    ARE_KILL_SCRIPTS_SHOWN,
    EC2_LOGIC,
    EXPECTED_TAGS,
    WHAT_NEED_TO_SHOWN,
    ALLOW_EMPTY,
    SEND_ON
};

const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditRDS = new CloudCoreoJSRunner(JSON, VARIABLES);
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
