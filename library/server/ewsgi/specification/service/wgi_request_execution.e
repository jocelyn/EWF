note
	description: "Summary description for {WGI_REQUEST_EXECUTION}."
	author: ""
	date: "$Date$"
	revision: "$Revision$"

deferred class
	WGI_REQUEST_EXECUTION

feature -- Access

	request: separate WGI_REQUEST

	response: separate WGI_RESPONSE

feature -- Execution

	execute
		deferred
			----			response.push !!
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
