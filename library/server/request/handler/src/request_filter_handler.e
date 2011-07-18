note
	description: "Summary description for REQUEST_FILTER_HANDLER."
	author: ""
	date: "$Date$"
	revision: "$Revision$"

deferred class
	REQUEST_FILTER_HANDLER

inherit
	REQUEST_HANDLER

feature -- Initialization

	make (a_next: REQUEST_HANDLER)
		do
			next := a_next
			initialize
		end

feature -- Access
	next: REQUEST_HANDLER

	stopped: BOOLEAN

feature -- Execution

	application_response (a_path: STRING; req: GW_REQUEST; a_format: detachable STRING; a_args: detachable STRING): GW_RESPONSE
		do
			stopped := False
			Result := handler_response (a_path, req, a_format, a_args)
			if not stopped then
				Result := next.application_response (a_path, req, a_format, a_args)
			end
		end

	handler_response (a_path: STRING; req: GW_REQUEST; a_format: detachable STRING; a_args: detachable STRING): GW_RESPONSE
			-- Fill `req.matching_response'
			-- and if decided set `stopped' to True, this way, `next' won't be processed
		deferred
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
