from typing import List, Optional

from pydantic import Field

from app.models.base import APIBaseModel
from app.models.resources import Resource


class Client(APIBaseModel):
    clientId: str = Field(description="Client id")
    name: Optional[str] = Field(None, description="Client name")
    description: Optional[str] = Field(None, description="Client description")
    secret: Optional[str] = Field(None, description="Client secret")
    rootUrl: Optional[str] = Field(None, description="Client root URL")
    adminUrl: Optional[str] = Field(None, description="Client admin URL")
    baseUrl: Optional[str] = Field(None, description="Client base URL")
    redirectUris: Optional[List[str]] = Field(['*'], description="Client Redirect URIs")
    webOrigins: Optional[List[str]] = Field(['*'], description="Client Web origins")
    protocol: Optional[str] = Field('openid-connect', description="Client protocol: openid-connect / SAML")
    defaultRoles: Optional[List[str]] = Field(None, description="Client Default roles")
    bearerOnly: Optional[bool] = Field(None, description="Enable/Disable Bearer only")
    consentRequired: Optional[bool] = Field(None, description="Enable/Disable Consent required")
    publicClient: Optional[bool] = Field(False, description="Disable/Enable authentication to the client")
    authorizationServicesEnabled: Optional[bool] = Field(True, description="Enable Authorization Services")
    serviceAccountsEnabled: Optional[bool] = Field(True,
                                                   description="Either or not to create a Service Account for the client")
    standardFlowEnabled: Optional[bool] = Field(True, description="Enable/Disable Standard Flow")
    implicitFlowEnabled: Optional[bool] = Field(None, description="Client name")
    directAccessGrantsEnabled: Optional[bool] = Field(None, description="Enable/Disable Direct Access Grants Flow")
    oauth2DeviceAuthorizationGrantEnabled: Optional[bool] = Field(None,
                                                                  description="Enable/Disable OAuth2 Device Authorization Grant Flow")
    directGrantsOnly: Optional[bool] = Field(None, description="Enable/Disable Direct Grants Flow")
    resources: Optional[List[Resource]] = Field([], description="List of resources to be added to the client")