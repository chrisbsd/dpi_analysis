TLS/SSL certificate analysis
--------------------------------------------

This tool is a little program I created to help administrators to get a quick review of their TLS/SSL certificates and
additional information about it. It can be used on all systems and no GUI is required. If you want to compile it use
the build command of golang.
Created by: chrisbsd


#### Usage:

* Clone the repository and cd into it
* Get information about the tool:
    go run ssl_analysis.go help
* List a quick listing of the available headers:
    go run ssl_analysis.go options
* Start it using your website: go run ssl_analysis.go https://www.yourwebsite.com


If you have any questions regarding this tool contact me: chsieger@secomos.de