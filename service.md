Here are the inferred HTTP contracts from your handler signatures and comments. Since the exact domain.* structs are not shown, this is reconstructed from usage, comments, and conventions in the handler layer.

Public Auth Endpoints

POST /auth/register

Request

{
  "email": "user@example.com",
  "password": "super-secret-password",
  "first_name": "Adrian",
  "last_name": "Mwicigi",
  "country": "KE"
}

Response 201 Created

Headers:

X-Zookie: <zookie-token>

Body:

{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "first_name": "Adrian",
    "last_name": "Mwicigi",
    "country": "KE",
    "created_at": "2026-05-27T12:00:00Z"
  },
  "zookie": "opaque-zookie-token"
}


---

POST /auth/login

Request

{
  "email": "user@example.com",
  "password": "super-secret-password"
}

Response 200 OK

{
  "access_token": "jwt-access-token",
  "refresh_token": "jwt-refresh-token",
  "expires_in": 900
}


---

Context Activation

POST /auth/context/activate

Protected endpoint.

Authorization Header

Authorization: Bearer <access-token>

Request

{
  "user_id": "uuid",
  "actor_id": "0x123456",
  "actor_type": "DRIVER",
  "permissions": [
    "trip.start",
    "booking.view"
  ],
  "delegated_permissions": [],
  "policy_groups": [
    "drivers-group"
  ]
}

Response 200 OK

{
  "access_token": "context-jwt-token",
  "refresh_token": "refresh-token",
  "expires_in": 900
}

This token likely embeds:

actor context

permissions

delegation chain

policy groups


Like a permissions exosuit wrapped around the user identity. 🛰️


---

User APIs

GET /users

Protected endpoint.

Optional Query Params

?page=1
&page_size=20
&country=KE

Optional Header

X-Zookie: <consistency-token>

Response

{
  "items": [
    {
      "id": "uuid",
      "email": "user@example.com",
      "country": "KE"
    }
  ],
  "page": 1,
  "page_size": 20,
  "total": 1
}


---

GET /users/{id}

Protected endpoint.

Optional Header

X-Zookie: <consistency-token>

Response

{
  "id": "uuid",
  "email": "user@example.com",
  "first_name": "Adrian",
  "last_name": "Mwicigi",
  "country": "KE",
  "created_at": "2026-05-27T12:00:00Z"
}


---

PUT /users/{id}

Protected endpoint.

Request

{
  "first_name": "Morio",
  "last_name": "Anenza",
  "country": "KE"
}

Response

Headers:

X-Zookie: <zookie-token>

Body:

{
  "user": {
    "id": "uuid",
    "first_name": "Morio",
    "last_name": "Anenza",
    "country": "KE"
  },
  "zookie": "opaque-zookie-token"
}


---

DELETE /users/{id}

Protected endpoint.

Response

{
  "message": "user deleted",
  "zookie": "opaque-zookie-token"
}


---

Service Account APIs

POST /auth/service/token

Request

{
  "client_id": "payments-service",
  "client_secret": "super-secret"
}

Response

{
  "access_token": "service-access-token",
  "refresh_token": "service-refresh-token",
  "expires_in": 900
}


---

POST /service-accounts

Protected endpoint.

Request

{
  "client_id": "payments-service",
  "name": "Payments Service",
  "client_secret": "super-secret",
  "permissions": [
    "payments.read",
    "payments.write"
  ]
}

Response

Headers:

X-Zookie: <zookie-token>

Body:

{
  "service_account": {
    "client_id": "payments-service",
    "name": "Payments Service",
    "permissions": [
      "payments.read",
      "payments.write"
    ],
    "active": true,
    "created_at": "2026-05-27T12:00:00Z"
  },
  "zookie": "opaque-zookie-token"
}

Notice:

sa.SecretHash = ""

So hashes are explicitly stripped before serialization. Good containment boundary.


---

DELETE /service-accounts/{client_id}

Protected endpoint.

Response

{
  "message": "service account deactivated",
  "zookie": "opaque-zookie-token"
}


---

Health Endpoints

GET /health

Response

{
  "status": "ok",
  "time": "2026-05-27T12:00:00Z"
}


---

GET /ready

Healthy

{
  "status": "ready"
}

Unhealthy

HTTP 503

{
  "status": "not ready"
}


---

Standard Error Contracts

400

{
  "error": "malformed request body"
}

or

{
  "error": "invalid input"
}


---

401

{
  "error": "invalid credentials"
}

or

{
  "error": "token expired"
}

or

{
  "error": "invalid token"
}


---

403

{
  "error": "forbidden"
}


---

404

{
  "error": "user not found"
}


---

409

{
  "error": "user already exists"
}


---

429

{
  "error": "rate limit exceeded"
}


---

500

{
  "error": "internal server error"
}

The handler is pleasantly disciplined. Very “transport layer only, business logic quarantined elsewhere.” Like a customs checkpoint that stamps passports but never pilots the aircraft. ✈️
