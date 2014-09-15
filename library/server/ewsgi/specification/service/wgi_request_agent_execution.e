note
	description: "Summary description for {WGI_REQUEST_AGENT_EXECUTION}."
	author: ""
	date: "$Date$"
	revision: "$Revision$"

class
	WGI_REQUEST_AGENT_EXECUTION

inherit
	WGI_REQUEST_EXECUTION

create
	make

feature {NONE} -- Initialization

	make (agt: like procedure; a_request: like request; a_response: like response)
		do
			request := a_request
			response := a_response
			procedure := agt
		end

feature {NONE} -- Access

	procedure: PROCEDURE [ANY, TUPLE [like request, like response]]

feature -- Execution

	execute
		do
			procedure.call ([request, response])
		end

note
	copyright: "2011-2014, Jocelyn Fiat, Javier Velilla, Eiffel Software and others"
	license: "Eiffel Forum License v2 (see http://www.eiffel.com/licensing/forum.txt)"
	source: "[
			Eiffel Software
			5949 Hollister Ave., Goleta, CA 93117 USA
			Telephone 805-685-1006, Fax 805-685-6869
			Website http://www.eiffel.com
			Customer support http://support.eiffel.com
		]"
end
