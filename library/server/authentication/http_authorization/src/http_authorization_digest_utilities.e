note
	description: "Summary description for {HTTP_AUTHORIZATION_DIGEST_UTILITIES}."
	author: ""
	date: "$Date$"
	revision: "$Revision$"

class
	HTTP_AUTHORIZATION_DIGEST_UTILITIES

feature -- Digest computation

	digest_hash_of_username_realm_and_password (a_server_username: READABLE_STRING_8; a_server_realm: READABLE_STRING_8; a_server_password: READABLE_STRING_8; a_server_algorithm: detachable READABLE_STRING_8; a_server_nonce: READABLE_STRING_8): STRING_8
			-- hash value of `a_server_username' , `a_server_realm', and `a_server_password',
			-- also known as HA1 in the related wikipedia page.
			--
			-- If the algorithm directive's value is "MD5" or unspecified, then HA1 is
			--    {HA1} = {MD5}({A1}) = {MD5}( {username} : {realm} : {password} )
			--
 			-- If the algorithm directive's value is "MD5-sess", then HA1 is
			--    {HA1} = {MD5}({A1}) = {MD5}({MD5}( {username} : {realm} : {password} ) : {nonce} : {cnonce} )			
		local
			a1: STRING_8
		do
			check is_md5_algorithm: a_server_algorithm = Void or else a_server_algorithm.is_case_insensitive_equal_general ("md5") end
			create a1.make_from_string (a_server_username)
			a1.append_character (':')
			a1.append (a_server_realm)
			a1.append_character (':')
			a1.append (a_server_password)
			Result := md5_hash (a1)

			debug ("http_authorization")
				io.put_string ("Computed HA1: " + Result + "%N")
			end
		end

	digest_hash_of_method_and_uri (a_server_method: READABLE_STRING_8; a_server_uri: READABLE_STRING_8; a_server_algorithm: detachable READABLE_STRING_8; a_server_qop: detachable READABLE_STRING_8; for_auth_info: BOOLEAN): STRING_8
			-- hash value of `a_server_method' , and `a_server_uri',
			-- also known as HA2 in the related wikipedia page.
			-- `for_auth_info' MUST be set to True if we compute the hash for the Authentication-Info header.
			--
			-- If the qop directive's value is "auth" or is unspecified, then HA2 is
			--    {HA2} = {MD5}({A2}) = {MD5}( {method} : {digestURI} )
			--
			-- If the qop directive's value is "auth-int", then HA2 is
			--    {HA2} = {MD5}({A2}) = {MD5}( {method} : {digestURI} :  {MD5}(entityBody)) 			
		local
			a2: READABLE_STRING_8
		do
			check is_auth_qop: a_server_qop = Void or else a_server_qop.is_case_insensitive_equal_general ("auth") end
				-- Special treatment of Authentication-Info header.
			if for_auth_info then
				a2 := ":" + a_server_uri
			else
				a2 := a_server_method + ":" + a_server_uri
			end

			Result := md5_hash (a2)

			debug ("http_authorization")
				io.put_string ("Computed HA2: " + Result + "%N")
			end
		end

	digest_expected_response (ha1: READABLE_STRING_8; ha2: READABLE_STRING_8; a_server_nonce: READABLE_STRING_8; a_server_qop: detachable READABLE_STRING_8; server_algorithm: detachable READABLE_STRING_8; a_nc: detachable READABLE_STRING_8; a_cnonce: detachable READABLE_STRING_8) : STRING_8
			-- UNQUOTED expected response.
			-- also known as response in the related wikipedia page.
			--
			-- If the qop directive's value is "auth" or "auth-int", then compute the response as follows:
			--    {response} = {MD5}( {HA1} : {nonce} : {nonceCount} : {clientNonce} : {qop} : {HA2} )
			--
			-- If the qop directive is unspecified, then compute the response as follows:
			--    {response} = {MD5}( {HA1} : {nonce} : {HA2} ) 			
		local
			unhashed_response: READABLE_STRING_8
		do
			create Result.make_empty

			if a_server_qop /= Void then
				if a_nc /= Void and a_cnonce /= Void then
						-- Standard (for digest) computation of response.
					unhashed_response := ha1 + ":" + a_server_nonce + ":" + a_nc + ":" + a_cnonce + ":" + a_server_qop + ":" + ha2
					debug ("http_authorization")
						io.put_string ("Expected unhashed response: " + unhashed_response)
						io.new_line
					end

					Result := md5_hash (unhashed_response)
					debug ("http_authorization")
						io.put_string ("Expected unquoted response: " + Result)
						io.new_line
					end
				else
						-- TODO Throw an exception. This should be excluded by invariant.
					debug ("http_authorization")
						io.put_string ("ERROR: This should not happen!%N")
					end
				end
			else
					-- qop directive is not present.
					-- Use construction for backwards compatibility with RFC 2069
				debug ("http_authorization")
					io.put_string ("RFC 2069 mode.")
					io.new_line
				end
				unhashed_response := ha1 + ":" + a_server_nonce + ":" + ha2
				Result := md5_hash (unhashed_response)
			end
		end

feature {HTTP_AUTHORIZATION} -- Helpers: hash, md5		

	md5_hash (s: READABLE_STRING_8): STRING_8
		local
			hash: MD5
		do
			create hash.make
			hash.update_from_string (s)
			Result := hash.digest_as_string
			Result.to_lower
		end

end
