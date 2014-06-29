note
	description: "Test digest access authentication, as well as user- and nonce-managers"

class
	TESTING

create
	test

feature

	test
		do
			create user_manager.make
			create nonce_manager.make(2)

				-- Init credentials.
			user_manager.put_credentials ("eiffel", "world")
			user_manager.put_credentials ("geschke", "geheim")

				-- Init constants.
			http_method := "GET"

				-- Perform checks.
			digest_check
			rspauth_check
			nonce_manager_check
			user_manager_check
			basic_check

				-- Terminated successfully.
			io.putstring ("%NPassed all checks!%N%N")
		end

feature -- Managers

		user_manager: MEMORY_USER_MANAGER
		nonce_manager: MEMORY_NONCE_MANAGER

feature -- Constants

	http_method: STRING

feature -- Tests

	digest_check
			-- Check digest parsing and response.
			-- Includes checking the authorization, is_bad_request flag and stale flag.
			-- NOTE: The stale flag is only set, if the response matches the expectation (i.e., the stale flag being set implies that the response is as expected).
		do
			debug ("http-auth testing")
				io.putstring ("Checking digest...%N")
			end

			check
					-- Standard
				check_response_digest ("Digest username=%"geschke%", realm=%"LUG-Erding%", nonce=%"3E4qOR2IBAA=afd655f551e63c0f239f118842d2a0e002d92593%", uri=%"/digest/%", algorithm=MD5, response=%"006507c9201068d1d42546f2b65bb7ba%", qop=auth, nc=00000001, cnonce=%"a5a3399a2aa0895c%"", true, false, false)

					-- Wrong response
				check_response_digest ("Digest username=%"geschke%", realm=%"LUG-Erding%", nonce=%"3E4qOR2IBAA=afd655f551e63c0f239f118842d2a0e002d92593%", uri=%"/digest/%", algorithm=MD5, response=%"00000000000000000000000000000000%", qop=auth, nc=00000001, cnonce=%"a5a3399a2aa0895c%"", false, false, false)

					-- Without qop
				check_response_digest ("Digest username=%"eiffel%", realm=%"testrealm@host.com%", nonce=%"U2F0LCAyNCBNYXkgMjAxNCAwODo0ODozMiBHTVQ6Y2UyYWNjODIxYWVlNTA1OWIwMGIxOWIzNDc3MDk3NDk=%", uri=%"/login%", algorithm=MD5, response=%"060135c5e618128e2759061defe8c8dc%", opaque=%"5ccc069c403ebaf9f0171e9517f40e41%"", true, false, false)

					-- Wrong qop
				check_response_digest ("Digest username=%"geschke%", realm=%"LUG-Erding%", nonce=%"3E4qOR2IBAA=afd655f551e63c0f239f118842d2a0e002d92593%", uri=%"/digest/%", algorithm=MD5, response=%"006507c9201068d1d42546f2b65bb7ba%", qop=auth-int, nc=00000001, cnonce=%"a5a3399a2aa0895c%"", false, false, true)

					-- Without algorithm
				check_response_digest ("Digest username=%"eiffel%", realm=%"testrealm@host.com%", nonce=%"U2F0LCAyNCBNYXkgMjAxNCAxMToyNzo0OCBHTVQ6OTdhYTBmYTEzOWNlODg1OTJiM2M2ZTUwYTEwODc3ZmI=%", uri=%"/login%", qop=auth, response=%"aa5b9592e3b2aa1da186caac3b8c3d82%", opaque=%"5ccc069c403ebaf9f0171e9517f40e41%", nc=00000001, cnonce=%"220d8c34daa301b9%"", true, false, false)

					-- Wrong algorithm
				check_response_digest ("Digest username=%"geschke%", realm=%"LUG-Erding%", nonce=%"3E4qOR2IBAA=afd655f551e63c0f239f118842d2a0e002d92593%", uri=%"/digest/%", algorithm=MD5-sess, response=%"006507c9201068d1d42546f2b65bb7ba%", qop=auth, nc=00000001, cnonce=%"a5a3399a2aa0895c%"", false, false, true)

					-- Without qop and algorithm
				check_response_digest ("Digest username=%"eiffel%", realm=%"testrealm@host.com%", nonce=%"U2F0LCAyNCBNYXkgMjAxNCAxMTozMzoyNiBHTVQ6ZDFiNjQxYjUyNmYzMTMzNjhiMzJhZDFjMjkyMzgxZmQ=%", uri=%"/login%", response=%"631b74f544c67c8cdf8a37dc139cc320%", opaque=%"5ccc069c403ebaf9f0171e9517f40e41%"", true, false, false)
			end
		end

	rspauth_check
			-- Check rspauth for digest.
			-- Try to recompute rspauth from this example: http://www.lug-erding.de/artikel/HTTPundSquid.html
		local
			auth: HTTP_AUTHORIZATION
			authorization_string: STRING
			www_authenticate_string: STRING
			login, password, realm, uri, algorithm, qop, nonce: STRING
			HA1, HA2: STRING
			rspauth: STRING
			authentication_method: STRING
		do
			debug ("http-auth testing")
				io.putstring ("Checking rspauth...%N")
			end

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
		end

	nonce_manager_check
			-- Check nonce-manager.
			-- Includes checking whether the manager knows which nonces exist and which not,
			-- and whether a nonce is stale or not.
		local
			exec_environment: EXECUTION_ENVIRONMENT
			l_nonce: STRING
		do
			debug ("http-auth testing")
				io.putstring ("Checking nonce manager...%N")
			end

			create exec_environment

				-- Unknown nonce
			check
				not nonce_manager.nonce_exists ("a2F0LCAyNCBNYXkgMjAxNCAxMTozMzoyNiBHTVQ6ZDFiNjQxYjUyNmYzMTMzNjhiMzJhZDFjMjkyMzgxZmQ=%"")
			end

				-- Not stale
			l_nonce := nonce_manager.new_nonce

			check
				not_stale: not nonce_manager.is_nonce_stale (l_nonce)
			end

			exec_environment.sleep (3000000000)

				-- Stale
			check
				stale: nonce_manager.is_nonce_stale (l_nonce)
			end
		end

	user_manager_check
			-- Check user-manager
			-- Includes checking whether the manager knows which users exist and which not.
		do
			debug ("http-auth testing")
				io.putstring ("Checking user manager...%N")
			end
				-- Unknown user
			check
				not user_manager.user_exists ("Damian")
				not user_manager.user_exists ("Eiffel")
			end

				-- Known user
			check
				user_manager.user_exists ("eiffel")
			end
		end

	basic_check
			-- Check basic authentication.
			-- This check basically tests the BASE64 en- and decoding, and is not really necessary here.
		do
			debug ("http-auth testing")
				io.putstring ("Checking basic...%N")
			end

			check
				-- Basic correct
				((create {BASE64}).decoded_string ("ZWlmZmVsOndvcmxk")).same_string("eiffel:world")

					-- Wrong password
				not ((create {BASE64}).decoded_string ("ZWlmZmVsOndvcmw=")).same_string("eiffel:world")

					-- Wrong username
				not ((create {BASE64}).decoded_string ("ZWlmZmU6d29ybGQ=")).same_string("eiffel:world")

					-- Everything wrong
				not ((create {BASE64}).decoded_string ("Arbitrary")).same_string("eiffel:world")
			end
		end


feature -- Digest response

	check_response_digest (authorization_string: STRING; a_stale_expected: BOOLEAN; a_authorization_expected: BOOLEAN; a_bad_request_expected: BOOLEAN): BOOLEAN
			-- True if the authorization, is_bad_request flag and stale flag are as expected.
		local
			auth: HTTP_AUTHORIZATION
			authorized: BOOLEAN
		do
				-- NOTE: The nonce in the Authorization header we check does not have our format.
				-- Therefore the nonce-manager will tell us that the time from the nonce is in 1970.
			create auth.make (authorization_string)

			if auth.is_bad_request then
				Result := (auth.is_bad_request = a_bad_request_expected)
			elseif
				attached auth.digest_data as d and attached auth.login as l_login
			then
					-- Add the nonce, if necessary.
				if not nonce_manager.nonce_exists (d.nonce) then
					nonce_manager.add_nonce (d.nonce)
				end

				authorized := auth.is_authorized_digest (nonce_manager, user_manager, d.realm, http_method, d.uri, d.algorithm, d.qop)

				Result := (auth.is_bad_request = a_bad_request_expected) and (auth.stale = a_stale_expected) and (authorized = a_authorization_expected)

				if not Result then
					io.putstring ("Authorized: " + authorized.out + ", expected: " + a_authorization_expected.out + "%N")
					io.putstring ("Bad request: " + auth.is_bad_request.out + ", expected: " + a_bad_request_expected.out + "%N")
					io.putstring ("Stale: " + auth.stale.out + ", expected: " + a_stale_expected.out + "%N")
				end
			else
				io.putstring ("This is not allowed to happen.")
				check False end
			end
		end
end
