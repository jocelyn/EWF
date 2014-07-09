note
	description: "[
			Component to launch the service using the default connector

				Eiffel Web Nino for this class


				The Nino default connector support options:
					port: numeric such as 8099 (or equivalent string as "8099")
					base: base_url (very specific to standalone server)
					verbose: to display verbose output, useful for Nino
					force_single_threaded: use only one thread, useful for Nino
					max_concurrent_connections: set max concurrent connections useful for concurrent nino

			check WSF_SERVICE_LAUNCHER for more documentation
		]"
	date: "$Date$"
	revision: "$Revision$"

class
	WSF_NINO_SERVICE_LAUNCHER

inherit
	WSF_SERVICE_LAUNCHER
		redefine
			launchable
		end

create
	make,
	make_and_launch,
	make_callback,
	make_callback_and_launch

feature {NONE} -- Initialization

	initialize
		local
			conn: like connector
		do
			create on_launched_actions
			create on_stopped_actions

			port_number := 80 --| Default, but quite often, this port is already used ...
			base_url := ""

			if attached options as opts then
				if attached {READABLE_STRING_GENERAL} opts.option ("server_name") as l_server_name then
					server_name := l_server_name.to_string_8
				end
				if attached {INTEGER} opts.option ("port") as l_port then
					port_number := l_port
				elseif
					attached {READABLE_STRING_GENERAL} opts.option ("port") as l_port_str and then
					l_port_str.is_integer
				then
					port_number := l_port_str.as_string_8.to_integer
				end
				if attached {READABLE_STRING_GENERAL} opts.option ("base") as l_base_str then
					base_url := l_base_str.as_string_8
				end
				if
					attached {READABLE_STRING_GENERAL} opts.option ("max_concurrent_connections") as l_max_concurrent_connections and then
					l_max_concurrent_connections.is_integer
				then
					max_concurrent_connections := l_max_concurrent_connections.to_integer
				else
					max_concurrent_connections := 50
				end
				if
					(attached {BOOLEAN} opts.option ("force_single_threaded") as l_single_threaded and then l_single_threaded)
					or (
						attached {READABLE_STRING_GENERAL} opts.option ("force_single_threaded") as l_single_threaded_str and then
						l_single_threaded_str.as_lower.same_string ("true")
					)
				then
					max_concurrent_connections := 0
				end
				if
					(attached {BOOLEAN} opts.option ("verbose") as l_verbose and then l_verbose)
					or (
						attached {READABLE_STRING_GENERAL} opts.option ("verbose") as l_verbose_str and then
						l_verbose_str.as_lower.same_string ("true")
					)
				then
					verbose := True
				else
					verbose := False
				end
			end
			create conn.make (Current)
			connector := conn
			conn.on_launched_actions.extend (agent on_launched)
			conn.on_stopped_actions.extend (agent on_stopped)
		end

feature -- Execution

	launch
			-- <Precursor/>
			-- using `port_number', `base_url', `verbose' and `max_concurrent_connections'
		do
			if attached connector as conn then
				conn.configuration.set_max_concurrent_connections (max_concurrent_connections)
				conn.configuration.set_is_verbose (verbose)
				conn.set_base (base_url)
				debug ("nino")
					if verbose then
						io.error.put_string ("Launching Nino web server on port " + port_number.out)
						if attached server_name as l_name then
							io.error.put_string ("%N http://" + l_name + ":" + port_number.out + "/" + base_url + "%N")
						else
							io.error.put_string ("%N http://localhost:" + port_number.out + "/" + base_url + "%N")
						end
					end
				end
				if attached server_name as l_server_name then
					conn.configuration.set_http_server_name (l_server_name)
				end
				conn.configuration.http_server_port := port_number
				conn.launch
			end
		end

feature -- Callback

	on_launched_actions: ACTION_SEQUENCE [TUPLE [WGI_CONNECTOR]]
			-- Actions triggered when launched

	on_stopped_actions: ACTION_SEQUENCE [TUPLE [WGI_CONNECTOR]]
			-- Actions triggered when stopped

feature {NONE} -- Implementation

	on_launched (conn: WGI_CONNECTOR)
		do
			on_launched_actions.call ([conn])
		end

	on_stopped (conn: WGI_CONNECTOR)
		do
			on_stopped_actions.call ([conn])
		end

	port_number: INTEGER

	server_name: detachable READABLE_STRING_8

	base_url: READABLE_STRING_8

	verbose: BOOLEAN

	max_concurrent_connections: INTEGER

feature -- Status report

	connector: detachable WGI_NINO_CONNECTOR
			-- Default connector

	launchable: BOOLEAN
		do
			Result := Precursor and port_number >= 0
		end

;note
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
