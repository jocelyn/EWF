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
			create user_manager.make
			create nonce_manager.make(10)

			user_manager.put_credentials ("eiffel", "world")
			user_manager.put_credentials ("geschke", "geheim")
			-- Checking digest.




			-- Checking rspauth.
			-- Try to recompute rspauth from this example: http://www.lug-erding.de/artikel/HTTPundSquid.html

			www_authenticate_string := "WWW-Authenticate: Digest realm=%"LUG-Erding%", nonce=%"3E4qOR2IBAA=afd655f551e63c0f239f118842d2a0e002d92593%", algorithm=MD5, domain=%"/digest%", qop=%"auth%""
			authorization_string := "Digest username=%"geschke%", realm=%"LUG-Erding%", nonce=%"3E4qOR2IBAA=afd655f551e63c0f239f118842d2a0e002d92593%", uri=%"/digest/%", algorithm=MD5, response=%"006507c9201068d1d42546f2b65bb7ba%", qop=auth, nc=00000001, cnonce=%"a5a3399a2aa0895c%""

			login := "geschke"
			password := "geheim"
			realm := "LUG-Erding"
			uri := "/digest/"
			algorithm := "MD5"
			qop := "auth"
			authentication_method := "Digest"
			nonce := "3E4qOR2IBAA=afd655f551e63c0f239f118842d2a0e002d92593"

			create auth.make (authorization_string)

			HA1 := auth.digest_hash_of_username_realm_and_password (login, realm, password, algorithm, nonce)

			HA2 := auth.digest_hash_of_method_and_uri (http_method, uri, algorithm, qop, True)

			rspauth := auth.digest_expected_response (HA1, HA2, nonce, qop, algorithm, "00000001", "a5a3399a2aa0895c")

			check
				rspauth.same_string ("a65658cb1cccea078b35c321a6ce3132");
			end

				-- Checking that the server computes the right expected response field.
			check
					-- Standard.
				check_response_digest ("Digest username=%"geschke%", realm=%"LUG-Erding%", nonce=%"3E4qOR2IBAA=afd655f551e63c0f239f118842d2a0e002d92593%", uri=%"/digest/%", algorithm=MD5, response=%"006507c9201068d1d42546f2b65bb7ba%", qop=auth, nc=00000001, cnonce=%"a5a3399a2aa0895c%"", true, false, false)

					-- With qop = auth, but wrong result.
					-- NOTE The stale flag is only set, if the response matches the expectation.
				check_response_digest ("Digest username=%"geschke%", realm=%"LUG-Erding%", nonce=%"3E4qOR2IBAA=afd655f551e63c0f239f118842d2a0e002d92593%", uri=%"/digest/%", algorithm=MD5, response=%"00000000000000000000000000000000%", qop=auth, nc=00000001, cnonce=%"a5a3399a2aa0895c%"", false, false, false)

					-- Without qop.
				check_response_digest ("Digest username=%"eiffel%", realm=%"testrealm@host.com%", nonce=%"U2F0LCAyNCBNYXkgMjAxNCAwODo0ODozMiBHTVQ6Y2UyYWNjODIxYWVlNTA1OWIwMGIxOWIzNDc3MDk3NDk=%", uri=%"/login%", algorithm=MD5, response=%"060135c5e618128e2759061defe8c8dc%", opaque=%"5ccc069c403ebaf9f0171e9517f40e41%"", true, false, false)

					-- Wrong qop
				check_response_digest ("Digest username=%"geschke%", realm=%"LUG-Erding%", nonce=%"3E4qOR2IBAA=afd655f551e63c0f239f118842d2a0e002d92593%", uri=%"/digest/%", algorithm=MD5, response=%"006507c9201068d1d42546f2b65bb7ba%", qop=auth-int, nc=00000001, cnonce=%"a5a3399a2aa0895c%"", false, false, true)

					-- Without algorithm
				check_response_digest ("Digest username=%"eiffel%", realm=%"testrealm@host.com%", nonce=%"U2F0LCAyNCBNYXkgMjAxNCAxMToyNzo0OCBHTVQ6OTdhYTBmYTEzOWNlODg1OTJiM2M2ZTUwYTEwODc3ZmI=%", uri=%"/login%", qop=auth, response=%"aa5b9592e3b2aa1da186caac3b8c3d82%", opaque=%"5ccc069c403ebaf9f0171e9517f40e41%", nc=00000001, cnonce=%"220d8c34daa301b9%"", true, false, false)

					-- Wrong algorithm
				check_response_digest ("Digest username=%"geschke%", realm=%"LUG-Erding%", nonce=%"3E4qOR2IBAA=afd655f551e63c0f239f118842d2a0e002d92593%", uri=%"/digest/%", algorithm=MD5-sess, response=%"006507c9201068d1d42546f2b65bb7ba%", qop=auth, nc=00000001, cnonce=%"a5a3399a2aa0895c%"", false, false, true)

					-- Without qop and algorithm
				check_response_digest ("Digest username=%"eiffel%", realm=%"testrealm@host.com%", nonce=%"U2F0LCAyNCBNYXkgMjAxNCAxMTozMzoyNiBHTVQ6ZDFiNjQxYjUyNmYzMTMzNjhiMzJhZDFjMjkyMzgxZmQ=%", uri=%"/login%", response=%"631b74f544c67c8cdf8a37dc139cc320%", opaque=%"5ccc069c403ebaf9f0171e9517f40e41%"", true, false, false)

					-- Everything ok, especially nonce not stale.
					
					-- Basic
				((create {BASE64}).decoded_string ("ZWlmZmVsOndvcmxk")).same_string("eiffel:world")

					-- Wrong password
				not ((create {BASE64}).decoded_string ("Arbitry")).same_string("eiffel:world")

					-- Wrong username

					-- Unknown nonce

					-- Stale nonce
			end

		end

feature -- Managers


			user_manager: MEMORY_USER_MANAGER
			nonce_manager: MEMORY_NONCE_MANAGER

feature -- Constants
	http_method: STRING = "GET"

feature

	check_response_digest (authorization_string: STRING; a_stale_expected: BOOLEAN; a_authorization_expected: BOOLEAN; a_bad_request_expected: BOOLEAN): BOOLEAN
			-- True if the computed response matches the expected response.
		local
			auth: HTTP_AUTHORIZATION
			authorized: BOOLEAN
			time: HTTP_DATE
		do
				-- NOTE: The nonce in the Authorization header we check does not have our format.
				-- Therefore the nonce-manager will tell us that the time from the nonce is in 1970.
			create auth.make (authorization_string)

			if
				attached auth.digest_data as d and then
				(
					attached d.realm as l_realm and
					attached d.uri as l_uri and
					attached auth.login as l_login and
					attached d.nonce as l_nonce
				)
			then
				if not nonce_manager.nonce_exists (l_nonce) then
					nonce_manager.add_nonce (l_nonce)
				end


				authorized := auth.is_authorized_digest (nonce_manager, user_manager, l_realm, http_method, l_uri, d.algorithm, d.qop)

				if a_bad_request_expected then
					Result := (auth.is_bad_request = a_bad_request_expected)
				else
					Result := (auth.is_bad_request = a_bad_request_expected) and (auth.stale = a_stale_expected) and (authorized = a_authorization_expected)
				end

				if not Result then
					io.putstring ("Authorized: " + authorized.out + ", expected: " + a_authorization_expected.out + "%N")
					io.putstring ("Bad request: " + auth.is_bad_request.out + ", expected: " + a_bad_request_expected.out + "%N")
					io.putstring ("Stale: " + auth.stale.out + ", expected: " + a_stale_expected.out + "%N")
				end

			else
				io.putstring ("This cannot happen.")
				check False end
			end

		end

end
