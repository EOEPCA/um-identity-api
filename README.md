# Identity API

Flask application to enable a REST API server to manage Keycloak through Keycloak Admin API (https://www.keycloak.org/docs-api/21.0.1/rest-api/index.html) and Protection API (https://www.keycloak.org/docs/latest/authorization_services/index.html#_service_protection_api).  
  
Includes three main paths:
- **Resources** - CRUD operations to manage resources
- **Policies** - CRUD operations to manage policies
- **Permissions** - CRUD operations to manage permissions


### Build and Execute

```shell
docker build -f identity-api/Dockerfile . -t identity-api:latest
docker run --rm -dp 5566:5566 --name identity-api identity-api:latest
```
