log_level = "TRACE"

plugin "boundary-driver-plugin" {
  config {
    enabled        = true
    boundary_addr  = "http://127.0.0.1:9200"
    auth_method_id = "ampw_1234567890"
    org_id         = "o_1234567890"
    username       = "admin"
    password       = "password"
  }
}
