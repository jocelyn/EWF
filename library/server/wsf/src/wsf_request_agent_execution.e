note
	description: "Summary description for {WSF_REQUEST_AGENT_EXECUTION}."
	author: ""
	date: "$Date$"
	revision: "$Revision$"

class
	WSF_REQUEST_AGENT_EXECUTION

inherit
	WSF_REQUEST_EXECUTION

create
	make

feature {NONE} -- Initialization

	make (agt: like procedure; a_request: WSF_REQUEST; a_response: WSF_RESPONSE)
		do
			request := a_request
			response := a_response
			procedure := agt
		end

feature {NONE} -- Access

	procedure: PROCEDURE [ANY, TUPLE [WSF_REQUEST, WSF_RESPONSE]]

feature -- Execution

	execute
		do
			procedure.call ([request, response])
		end

note
	copyright: "2011-2014, Jocelyn Fiat, Javier Velilla, Olivier Ligot, Colin Adams, Eiffel Software and others"
	license: "Eiffel Forum License v2 (see http://www.eiffel.com/licensing/forum.txt)"
	source: "[
			Eiffel Software
			5949 Hollister Ave., Goleta, CA 93117 USA
			Telephone 805-685-1006, Fax 805-685-6869
			Website http://www.eiffel.com
			Customer support http://support.eiffel.com
		]"
end
