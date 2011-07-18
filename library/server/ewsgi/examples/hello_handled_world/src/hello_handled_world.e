note
	description : "Objects that ..."
	author      : "$Author$"
	date        : "$Date$"
	revision    : "$Revision$"

class
	HELLO_HANDLED_WORLD

inherit
	HELLO_WORLD
		redefine
			make,
			execute
		end

create
	make

feature {NONE} -- Initialization

	make
		do
			initialize
			Precursor
		end

	initialize
		local
--			r: REQUEST_HANDLER
			ra: REQUEST_AGENT_HANDLER
			rg: REQUEST_GROUP_HANDLER
			authf: HELLO_AUTHENTICATION_HANDLER
		do
			create handler_manager.make (5)
			create ra.make (agent execute_hello)
			handler_manager.register ("/hello", ra)

			create ra.make (agent execute_doc)
			handler_manager.register ("/doc", ra)

			create ra.make (agent execute_account)
			create authf.make (ra)
			handler_manager.register ("/account", authf)

			create rg.make (2)
		end

	handler_manager: REQUEST_HANDLER_MANAGER


feature -- Execution

	execute (req: GW_REQUEST; res: GW_RESPONSE)
		do
			if attached handler_manager.handler (req) as r then
				r.execute (req.environment.request_uri, req, res)
			else
				execute_hello (req.environment.request_uri, req, res, Void, Void)
			end
		end

	execute_hello (path: STRING; req: GW_REQUEST; res: GW_RESPONSE; format: detachable STRING; args: detachable STRING)
		do
			res.write_header (200, <<["Content-Type", "text/plain"]>>)
			res.write_string ("Hello World!%N")
		end

	execute_doc (path: STRING; req: GW_REQUEST; res: GW_RESPONSE; format: detachable STRING; args: detachable STRING)
		do
			res.write_header (200, <<["Content-Type", "text/plain"]>>)
			res.write_string ("Documentation!%N")
		end

	execute_account (path: STRING; req: GW_REQUEST; res: GW_RESPONSE; format: detachable STRING; args: detachable STRING)
		do
			res.write_header (200, <<["Content-Type", "text/plain"]>>)
			res.write_string ("Account, this is private zone %N")
			if attached req.environment.http_authorization as l_auth then
				res.write_string ("Auth=" + (create {BASE64}).decoded_string (l_auth.substring (l_auth.index_of (' ', 1), l_auth.count)) + "%N")
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
