 job "example" {
   group "example" {
     task "boundary" {
       driver = "boundary-driver-plugin"
       config {
         create_role 		   = true
           create_host_catalog = true
           project_scope_id	   = "p_12345567890"

           credential_library {
             enabled             = true
             credential_store_id = ""
             path                = ""
           }
       }
     }
   }
 }

