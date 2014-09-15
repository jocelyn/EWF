note
	description: "Summary description for {WSF_REQUEST_EXECUTION_FACTORY}."
	author: ""
	date: "$Date$"
	revision: "$Revision$"

deferred class
	WSF_REQUEST_EXECUTION_FACTORY

feature -- Execution

	execution (req: WSF_REQUEST; res: WSF_RESPONSE): separate WSF_REQUEST_EXECUTION
		deferred
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
