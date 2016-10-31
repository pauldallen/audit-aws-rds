audit RDS
============================
This stack will monitor RDS and alert on things CloudCoreo developers think are violations of best practices


## Description
This repo is designed to work with CloudCoreo. It will monitor RDS against best practices for you and send a report to the email address designated by the config.yaml AUDIT&#95;AWS&#95;RDS&#95;ALERT&#95;RECIPIENT value


## Hierarchy
![composite inheritance hierarchy](https://raw.githubusercontent.com/CloudCoreo/audit-aws-rds/master/images/hierarchy.png "composite inheritance hierarchy")



## Required variables with no default

### `AUDIT_AWS_RDS_ALERT_RECIPIENT`:
  * description: email recipient for notification


## Required variables with default

### `AUDIT_AWS_RDS_ALERT_LIST`:
  * description: alert list for generating notifications
  * default: rds-short-backup-retention-period, rds-no-auto-minor-version-upgrade, rds-db-publicly-accessible

### `AUDIT_AWS_RDS_ALLOW_EMPTY`:
  * description: receive empty reports?
  * default: false

### `AUDIT_AWS_RDS_SEND_ON`:
  * description: always or change
  * default: change

### `AUDIT_AWS_RDS_REGIONS`:
  * description: list of AWS regions to check. Default is all regions
  * default: us-east-1, us-west-1, us-west-2


## Optional variables with no default

**None**


## Optional variables with default

**None**

## Tags
1. Audit
1. Best Practices
1. Alert
1. RDS

## Categories
1. Audit



## Diagram
![diagram](https://raw.githubusercontent.com/CloudCoreo/audit-aws-rds/master/images/diagram.png "diagram")


## Icon


