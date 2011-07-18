note
	description: "Summary description for {HELLO_AUTHENTICATION_HANDLER}."
	author: ""
	date: "$Date$"
	revision: "$Revision$"

class
	HELLO_AUTHENTICATION_HANDLER

inherit
	REQUEST_FILTER_HANDLER

create
	make

feature -- Execution

	handler_response (a_path: STRING; req: GW_REQUEST; a_format: detachable STRING; a_args: detachable STRING): GW_RESPONSE
		do
			Result := req.matching_response
			if attached req.environment.http_authorization as l_auth then
				-- Let's say this is ok ...
			else
				Result.write_header ({HTTP_STATUS_CODE}.unauthorized, <<["WWW-Authenticate", "Basic realm=%"Eiffel auth%""]>>)
				stopped := True
			end
		end

note
	copyright: "2011-2011, Eiffel Software and others"
	license: "Eiffel Forum License v2 (see http://www.eiffel.com/licensing/forum.txt)"
	source: "[
			Eiffel Software
			5949 Hollister Ave., Goleta, CA 93117 USA
			Telephone 805-685-1006, Fax 805-685-6869
			Website http://www.eiffel.com
			Customer support http://support.eiffel.com
		]"
end
