package com.github.bucchi.dbsc.verification;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.jose.jws.JWSInput;

import java.util.List;
import java.util.Map;

/** 

* DBSC-SSO登録リクエストの外側ペイロード（JSON）を表現するデータモデルクラス。
* Keycloak内蔵のJacksonを利用してマッピングします。
*/
@JsonIgnoreProperties(ignoreUnknown = true)
public class DBSCRegistrationStatement {

@JsonProperty("aud")
private String audience;

@JsonProperty("att")
private String attestation; // Base64URLエンコードされたattestation JSON object

@JsonProperty("jti")
private String innerJwsString; // 内側のJWS（通常のDBSC Proof）の生文字列 

// パース済みの内側キャッシュ（Jacksonの自動マッピングからは除外）
private InnerDBSCProof innerDbcProof;

public String getAudience() {
return audience;
}

public void setAudience(String audience) {
this.audience = audience;
}

public String getAttestation() {
return attestation;
}

public void setAttestation(String attestation) {
this.attestation = attestation;
}

public String getInnerJwsString() {
return innerJwsString;
}

public void setInnerJwsString(String innerJwsString) {
this.innerJwsString = innerJwsString;
}

/** 

  * jtiに格納されている内側のJWS文字列（通常のDBSC Proof）をパースし、
  * 最深部にあるSession Instructions（設計図）を取得するヘルパーメソッド。
*/
public InnerDBSCProof getInnerDbcProof() throws Exception {
if (this.innerDbcProof != null) {
return this.innerDbcProof;
}
if (this.innerJwsString == null || this.innerJwsString.isEmpty()) {
return null;
}

// 1. Keycloak内蔵のJWSInputを使って内側のJWSをパース
JWSInput innerJws = new JWSInput(this.innerJwsString);
String innerPayloadJson = new String(innerJws.getContent(), "UTF-8");

// 2. 最深部のJSONをInnerDBSCProofクラスにマッピング
ObjectMapper mapper = new ObjectMapper();
this.innerDbcProof = mapper.readValue(innerPayloadJson, InnerDBSCProof.class);
return this.innerDbcProof;
}
/** 

  * 最深部の通常のDBSCセッション設計図（Session Instructions）を表現するインナークラス
*/
@JsonIgnoreProperties(ignoreUnknown = true)
public static class InnerDBSCProof {
@JsonProperty("session_identifier")
private String sessionIdentifier;

@JsonProperty("refresh_url")
private String refreshUrl;

@JsonProperty("scope")
private Scope scope;

@JsonProperty("credentials")
private List credentials;

public String getSessionIdentifier() { return sessionIdentifier; }
public void setSessionIdentifier(String sessionIdentifier) { this.sessionIdentifier = sessionIdentifier; }

public String getRefreshUrl() { return refreshUrl; }
public void setRefreshUrl(String refreshUrl) { this.refreshUrl = refreshUrl; }

public Scope getScope() { return scope; }
public void setScope(Scope scope) { this.scope = scope; }

public List getCredentials() { return credentials; }
public void setCredentials(List credentials) { this.credentials = credentials; }
}

@JsonIgnoreProperties(ignoreUnknown = true)
public static class Scope {
@JsonProperty("origin")
private String origin;

@JsonProperty("include_site")
private boolean includeSite;

@JsonProperty("scope_specification")
private List<Map<String, Object>> scopeSpecification;

public String getOrigin() { return origin; }
public void setOrigin(String origin) { this.origin = origin; }

public boolean isIncludeSite() { return includeSite; }
public void setIncludeSite(boolean includeSite) { this.includeSite = includeSite; }

public List<Map<String, Object>> getScopeSpecification() { return scopeSpecification; }
public void setScopeSpecification(List<Map<String, Object>> scopeSpecification) { this.scopeSpecification = scopeSpecification; }
}

@JsonIgnoreProperties(ignoreUnknown = true)
public static class Credential {
@JsonProperty("type")
private String type;

@JsonProperty("name")
private String name;

@JsonProperty("attributes")
private String attributes;

public String getType() { return type; }
public void setType(String type) { this.type = type; }

public String getName() { return name; }
public void setName(String name) { this.name = name; }

public String getAttributes() { return attributes; }
public void setAttributes(String attributes) { this.attributes = attributes; }
}
}