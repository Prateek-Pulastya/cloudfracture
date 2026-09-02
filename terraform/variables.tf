# variables.tf — knobs for the whole stack.
# Region defaults to eu-central-1 (Frankfurt) to keep the lab close to the
# Berlin job market this portfolio targets; override per-session as needed.

variable "aws_region" {
  description = "AWS region the lab deploys into."
  type        = string
  default     = "eu-central-1"
}

variable "project" {
  description = "Name prefix for every resource. Also the tag Project value."
  type        = string
  default     = "cloudfracture"
}

# Phase 4 remediation toggle. false = the deliberately vulnerable build (all flaws
# live). true = the least-privilege remediated build (flaws closed). Apply with
# `-var secure_mode=true` and re-run the attacks to prove they now fail.
variable "secure_mode" {
  description = "false = vulnerable (default); true = least-privilege remediated."
  type        = bool
  default     = false
}
