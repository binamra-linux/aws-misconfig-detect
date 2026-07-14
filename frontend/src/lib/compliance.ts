import type { Finding } from "@/lib/api"

export interface ComplianceControl {
  control: string
  title: string
}

export const CIS_BENCHMARK_VERSION = "CIS AWS Foundations Benchmark v1.5.0"

const NOT_MAPPED: ComplianceControl = {
  control: "N/A",
  title: "General AWS security best practice -- not a numbered CIS AWS Foundations Benchmark v1.5.0 control.",
}

/**
 * Best-effort mapping to one specific benchmark version. Control numbers have
 * shifted across CIS AWS Foundations Benchmark releases (v1.2/v1.4/v1.5/v3.0) --
 * verify against the official document before citing these in anything formal.
 */
const CIS_MAP: Record<string, ComplianceControl> = {
  IAM_OVERLY_PERMISSIVE_POLICY: {
    control: "1.16",
    title: 'Ensure IAM policies that allow full "*:*" administrative privileges are not attached',
  },
  IAM_NO_MFA: {
    control: "1.2",
    title: "Ensure MFA is enabled for all IAM users that have a console password",
  },
  IAM_UNUSED_ACCESS_KEY: {
    control: "1.14 (approximate)",
    title:
      "Ensure access keys are rotated every 90 days or less -- our check flags unused keys, a related but not identical criterion",
  },
  ROOT_NO_MFA: {
    control: "1.5",
    title: "Ensure MFA is enabled for the 'root' user account",
  },
  ROOT_ACCESS_KEYS_PRESENT: {
    control: "1.4",
    title: "Ensure no 'root' user account access key exists",
  },
  CLOUDTRAIL_NOT_ENABLED: {
    control: "3.1",
    title: "Ensure CloudTrail is enabled in all regions",
  },
  CLOUDTRAIL_LOG_VALIDATION_DISABLED: {
    control: "3.2",
    title: "Ensure CloudTrail log file validation is enabled",
  },
  IAM_WEAK_PASSWORD_POLICY: {
    control: "1.8-1.11",
    title:
      "Ensure the IAM password policy requires a minimum length of 14 and at least one uppercase, lowercase, number and symbol",
  },
  SG_DEFAULT_ALLOWS_TRAFFIC: {
    control: "5.4",
    title: "Ensure the default security group of every VPC restricts all traffic",
  },
}

const SG_PORT_MAP: Record<number, ComplianceControl> = {
  22: { control: "5.2", title: "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22" },
  3389: { control: "5.3", title: "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389" },
}

export function getComplianceControl(finding: Finding): ComplianceControl {
  if (finding.check_type === "SG_OPEN_SENSITIVE_PORT") {
    const port = finding.detail?.port as number | undefined
    if (port && SG_PORT_MAP[port]) return SG_PORT_MAP[port]
    return {
      control: "N/A",
      title:
        "Not a dedicated CIS v1.5.0 control -- only ports 22/3389 are explicitly named; this covers a database port under the same general ingress-restriction principle.",
    }
  }

  return CIS_MAP[finding.check_type] ?? NOT_MAPPED
}
