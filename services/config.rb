
coreo_aws_advisor_alert "rds-short-backup-retention-period" do
  action :define
  service :rds
  link "http://kb.cloudcoreo.com/mydoc_rds-short-backup-retention-period.html"
  display_name "RDS short backup retention period"
  description "The affected RDS database has a short backup retention period (less than 30 days)."
  category "Dataloss"
  suggested_action "Modify the backup retension period to increase it to greater than 30 days."
  level "Alert"
  objectives ["db_instances"]
  audit_objects ["db_instances.backup_retention_period"]
  operators ["<"]
  alert_when [30]
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
end

coreo_aws_advisor_rds "advise-rds" do
  alerts ${AUDIT_AWS_RDS_ALERT_LIST}
  action :advise
  regions ${AUDIT_AWS_RDS_REGIONS}
end


=begin
  START AWS RDS METHODS
  JSON SEND METHOD
  HTML SEND METHOD
=end
coreo_uni_util_notify "advise-rds-json" do
  action :${AUDIT_AWS_RDS_FULL_JSON_REPORT}
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
                   :version => "1.0.8"
               }       ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "number_of_checks":"COMPOSITE::coreo_aws_advisor_rds.advise-rds.number_checks",
                "number_of_violations":"COMPOSITE::coreo_aws_advisor_rds.advise-rds.number_violations",
                "number_violations_ignored":"COMPOSITE::coreo_aws_advisor_rds.advise-rds.number_ignored_violations",
                "violations": COMPOSITE::coreo_aws_advisor_rds.advise-rds.report}'
  function <<-EOH
const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditRDS = new CloudCoreoJSRunner(json_input, false, "${AUDIT_AWS_RDS_ALERT_RECIPIENT_2}", "${AUDIT_AWS_RDS_OWNER_TAG}", 'rds');
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
for (var entry=0; entry < json_input.length; entry++) {
  console.log(json_input[entry]);
  if (json_input[entry]['endpoint']['to'].length) {
    console.log('got an email to rollup');
    rollup_string = rollup_string + "recipient: " + json_input[entry]['endpoint']['to'] + " - " + "nViolations: " + json_input[entry]['num_violations'] + "\\n";
  }
}
callback(rollup_string);
  EOH
end

coreo_uni_util_notify "advise-rds-to-tag-values" do
  action :${AUDIT_AWS_RDS_OWNERS_HTML_REPORT}
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-rds.return'
end

coreo_uni_util_notify "advise-rds-rollup" do
  action :${AUDIT_AWS_RDS_ROLLUP_REPORT}
  type 'email'
  allow_empty true
  send_on '${AUDIT_AWS_RDS_SEND_ON}'
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
number_of_checks: COMPOSITE::coreo_aws_advisor_rds.advise-rds.number_checks
number_of_violations: COMPOSITE::coreo_aws_advisor_rds.advise-rds.number_violations
number_violations_ignored: COMPOSITE::coreo_aws_advisor_rds.advise-rds.number_ignored_violations

rollup report:
COMPOSITE::coreo_uni_util_jsrunner.tags-rollup-rds.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_RDS_ALERT_RECIPIENT_2}', :subject => 'CloudCoreo rds advisor alerts on PLAN::stack_name :: PLAN::name'
  })
end
=begin
  AWS RDS END
=end
