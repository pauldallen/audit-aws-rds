
coreo_aws_advisor_alert "rds-short-backup-retention-period" do
  action :define
  service :rds
  link "http://kb.cloudcoreo.com/mydoc_rds-short-backup-retention-period.html"
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
  description "The affected RDS database is publicly accessible to the world."
  category "Security"
  suggested_action "Consider whether the affected RDS database should be publicly accessible to the world. If not, modify the option which enables your RDS database to become publicly accessible."
  level "Critical"
  objectives ["db_instances"]
  audit_objects ["db_instances.publicly_accessible"]
  operators ["=="]
  alert_when [false]
end

coreo_aws_advisor_rds "advise-rds" do
  alerts ${AUDIT_AWS_RDS_ALERT_LIST}
  action :advise
  regions ${AUDIT_AWS_RDS_REGIONS}
end

coreo_uni_util_notify "advise-rds" do
  action :notify
  type 'email'
  allow_empty ${AUDIT_AWS_RDS_ALLOW_EMPTY}
  send_on "${AUDIT_AWS_RDS_SEND_ON}"
  payload '{"stack name":"INSTANCE::stack_name",
  "instance name":"INSTANCE::name",
  "number_of_checks":"STACK::coreo_aws_advisor_rds.advise-rds.number_checks",
  "number_of_violations":"STACK::coreo_aws_advisor_rds.advise-rds.number_violations",
  "number_violations_ignored":"STACK::coreo_aws_advisor_rds.advise-rds.number_ignored_violations",
  "violations": STACK::coreo_aws_advisor_rds.advise-rds.report }'
  payload_type "${AUDIT_AWS_RDS_PAYLOAD_TYPE}"
  endpoint ({
      :to => '${AUDIT_AWS_RDS_ALERT_RECIPIENT}', :subject => 'CloudCoreo rds advisor alerts on INSTANCE::stack_name :: INSTANCE::name'
  })
end
