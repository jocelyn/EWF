note
	description: "Summary description for REQUEST_AGENT_HANDLER."
	author: ""
	date: "$Date$"
	revision: "$Revision$"

class
	REQUEST_AGENT_HANDLER

inherit
	REQUEST_HANDLER

create
	make

feature -- Initialization

	make (act: like action)
		do
			action := act
			initialize
		end

feature -- Access

	action: PROCEDURE [ANY, TUPLE [path: STRING; req: GW_REQUEST; res: GW_RESPONSE; format: detachable STRING; args: detachable STRING]]

feature -- Execution

	execute_application (a_path: STRING; req: GW_REQUEST; res: GW_RESPONSE; a_format: detachable STRING; a_args: detachable STRING)
		do
			action.call ([a_path, req, res, a_format, a_args])
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
