note
	description: "[
			HTTP stream socket, used to be used on a separate scoop region.
		]"
	date: "$Date$"
	revision: "$Revision$"

class
	HTTP_STREAM_SHADOW_SOCKET

inherit
	HTTP_STREAM_SOCKET
		redefine
			close
		end

create
	make_empty,
	make_from_separate

feature {NONE} -- Initialization

	make_from_separate (s: separate HTTP_STREAM_SOCKET)
		require
			s_with_address_set: s.address /= Void
		do
			if attached s.address as add then
				make_from_descriptor_and_address (s.descriptor, add)
			else
				make_empty
				check s_with_address_set: False end -- FALSE !!!
			end
		end

feature -- Basic commands

	close
		do
			-- Do nothing for this shadow socket ...
			-- TODO: check if this is acceptable.
		end

note
	copyright: "2011-2021, Jocelyn Fiat, Javier Velilla, Olivier Ligot, Colin Adams, Eiffel Software and others"
	license: "Eiffel Forum License v2 (see http://www.eiffel.com/licensing/forum.txt)"
	source: "[
			Eiffel Software
			5949 Hollister Ave., Goleta, CA 93117 USA
			Telephone 805-685-1006, Fax 805-685-6869
			Website http://www.eiffel.com
			Customer support http://support.eiffel.com
		]"

end
