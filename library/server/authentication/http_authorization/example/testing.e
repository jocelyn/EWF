note
	description: "Test digest access authentication."
	author: ""
	date: "$Date$"
	revision: "$Revision$"

class
	TESTING

create
	test

feature

	test
		local
			auth: HTTP_AUTHORIZATION
			authorization_string: STRING
			www_authenticate_string: STRING
			login, password, realm, method, uri, algorithm, qop, nonce: STRING
			HA1, HA2: STRING
			rspauth: STRING
			authentication_method: STRING
		do
			io.putstring ("TESTING... %N")

			www_authenticate_string := "WWW-Authenticate: Digest realm=%"LUG-Erding%", nonce=%"3E4qOR2IBAA=afd655f551e63c0f239f118842d2a0e002d92593%", algorithm=MD5, domain=%"/digest%", qop=%"auth%""
			authorization_string := "Digest username=%"geschke%", realm=%"LUG-Erding%", nonce=%"3E4qOR2IBAA=afd655f551e63c0f239f118842d2a0e002d92593%", uri=%"/digest/%", algorithm=MD5, response=%"006507c9201068d1d42546f2b65bb7ba%", qop=auth, nc=00000001, cnonce=%"a5a3399a2aa0895c%""
			io.putstring (authorization_string +"%N")

			login := "geschke"
			password := "geheim"
			realm := "LUG-Erding"
			uri := "/digest/"
			algorithm := "MD5"
			qop := "auth"
			method := "GET"
			authentication_method := "Digest"
			nonce := "3E4qOR2IBAA=afd655f551e63c0f239f118842d2a0e002d92593"


			create auth.make (authorization_string)

			HA1 := auth.digest_hash_of_username_realm_and_password (login, realm, password, algorithm, nonce)

			HA2 := auth.digest_hash_of_method_and_uri (method, uri, algorithm, qop, True)

			rspauth := auth.digest_expected_response (HA1, HA2, nonce, qop, algorithm, "00000001", "a5a3399a2aa0895c")

			check
				rspauth.same_string ("a65658cb1cccea078b35c321a6ce3132");
			end

			-- Testing that the server computes the right expected response field.
			check
				-- With qop = auth.
				check_response_digest (authentication_method, "geheim", "Digest username=%"geschke%", realm=%"LUG-Erding%", nonce=%"3E4qOR2IBAA=afd655f551e63c0f239f118842d2a0e002d92593%", uri=%"/digest/%", algorithm=MD5, response=%"006507c9201068d1d42546f2b65bb7ba%", qop=auth, nc=00000001, cnonce=%"a5a3399a2aa0895c%"", method)

				-- With qop = auth, but wrong result.
				not check_response_digest (authentication_method, "geheim", "Digest username=%"geschke%", realm=%"LUG-Erding%", nonce=%"3E4qOR2IBAA=afd655f551e63c0f239f118842d2a0e002d92593%", uri=%"/digest/%", algorithm=MD5, response=%"00000000000000000000000000000000%", qop=auth, nc=00000001, cnonce=%"a5a3399a2aa0895c%"", method)

				-- Without qop.
				check_response_digest (authentication_method, "world" , "Digest username=%"eiffel%", realm=%"testrealm@host.com%", nonce=%"U2F0LCAyNCBNYXkgMjAxNCAwODo0ODozMiBHTVQ6Y2UyYWNjODIxYWVlNTA1OWIwMGIxOWIzNDc3MDk3NDk=%", uri=%"/login%", algorithm=MD5, response=%"060135c5e618128e2759061defe8c8dc%", opaque=%"5ccc069c403ebaf9f0171e9517f40e41%"", method)

				-- Without algorithm
				check_response_digest (authentication_method, "world" , "Digest username=%"eiffel%", realm=%"testrealm@host.com%", nonce=%"U2F0LCAyNCBNYXkgMjAxNCAxMToyNzo0OCBHTVQ6OTdhYTBmYTEzOWNlODg1OTJiM2M2ZTUwYTEwODc3ZmI=%", uri=%"/login%", qop=auth, response=%"aa5b9592e3b2aa1da186caac3b8c3d82%", opaque=%"5ccc069c403ebaf9f0171e9517f40e41%", nc=00000001, cnonce=%"220d8c34daa301b9%"", method)

				-- Without qop and algorithm
				check_response_digest (authentication_method, "world" , "Digest username=%"eiffel%", realm=%"testrealm@host.com%", nonce=%"U2F0LCAyNCBNYXkgMjAxNCAxMTozMzoyNiBHTVQ6ZDFiNjQxYjUyNmYzMTMzNjhiMzJhZDFjMjkyMzgxZmQ=%", uri=%"/login%", response=%"631b74f544c67c8cdf8a37dc139cc320%", opaque=%"5ccc069c403ebaf9f0171e9517f40e41%"", method)

				-- Basic
				((create {BASE64}).decoded_string ("ZWlmZmVsOndvcmxk")).same_string("eiffel:world")

				-- Wrong Basic
				not ((create {BASE64}).decoded_string ("Arbitry")).same_string("eiffel:world")
			end

		end

feature

	check_response_digest (authentication_method: STRING; password: STRING; authorization_string: STRING; http_method: STRING): BOOLEAN
			-- Returns True iff the computed response matches the expected response.
		local
			auth: HTTP_AUTHORIZATION
			authorized: BOOLEAN
			nonces: ARRAYED_LIST[STRING_8]
		do
			create auth.make (authorization_string)

			if
				attached auth.digest_data as d and then(
				attached d.realm as attached_auth_realm and
				attached d.uri as attached_auth_uri and
				attached auth.login as attached_auth_login and
				attached d.nonce as attached_auth_nonce)
			then
				create nonces.make (0)

				nonces.force (attached_auth_nonce)

				authorized := auth.is_authorized_digest (attached_auth_login, password, attached_auth_realm, nonces, http_method, attached_auth_uri, d.algorithm, d.qop)

				Result := authorized and not auth.is_bad_request
			else
				io.putstring ("This cannot happen.")
			end

		end

end
