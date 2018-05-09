# Admiral Local User Manager

##### Provides a web UI for managing the local users within VMware [Admiral](https://github.com/vmware/admiral#what-is-admiral)

*The point of the web interface is for simply creating and deleting local admiral users.
Once users are created, they should be managed through the main Admiral UI.*

*__NOTE:__ You must log in using a cloud-admin account*

#### Running:
##### Docker:

Available as a docker container image: http://hub.docker.com/r/logankimmel/admiral-idm .
The docker image supports the environment variable `ADMIRAL_ENDPOINT` to specify the admiral in which to manage.

`docker run -d -e ADMIRAL_ENDPOINT="http://admiral.localdomain:8282" logankimmel/admiral`

##### Manually:
`go run main.go`
