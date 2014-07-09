note
	description: "Summary description for {WGI_NINO_REQUEST_HANDLER_FACTORY}."
	author: ""
	date: "$Date$"
	revision: "$Revision$"

class
	WGI_NINO_REQUEST_HANDLER_FACTORY

inherit
	HTTPD_REQUEST_HANDLER_FACTORY

create
	make

feature {NONE} -- Initialization

	make (conn: like connector)
		do
			connector := conn
		end

feature -- Access

	connector: WGI_NINO_CONNECTOR

feature -- Factory

	new_handler: WGI_NINO_CONNECTION_HANDLER
		do
			create Result.make (connector)
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
