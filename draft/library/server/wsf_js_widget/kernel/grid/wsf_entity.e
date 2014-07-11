note
	description: "Summary description for {WSF_ENTITY}."
	date: "$Date$"
	revision: "$Revision$"

deferred class
	WSF_ENTITY

feature -- Access

	item alias "[]" (a_field: READABLE_STRING_GENERAL): detachable ANY
			-- Value for field item `a_field'.
		deferred
		end

note
	copyright: "2011-2014, Yassin Hassan, Severin Munger, Jocelyn Fiat, Eiffel Software and others"
	license: "Eiffel Forum License v2 (see http://www.eiffel.com/licensing/forum.txt)"
	source: "[
			Eiffel Software
			5949 Hollister Ave., Goleta, CA 93117 USA
			Telephone 805-685-1006, Fax 805-685-6869
			Website http://www.eiffel.com
			Customer support http://support.eiffel.com
		]"
end
