note
	description: "Summary description for {REQUEST_HANDLER_PARAMETER}."
	date: "$Date$"
	revision: "$Revision$"

class
	REQUEST_HANDLER_PARAMETER

create
	make

feature {NONE} -- Initialization

	make (n: like name; opt: BOOLEAN)
		do
			name := n
			optional := opt
		end

feature -- Access

	name: STRING
			-- Parameter's name
			--| either field's name for GET,POST, ... variables
			--| or parameters in URI such as foo/{foo}

	optional: BOOLEAN
			-- Optional parameters

	value_name: detachable STRING
			-- Parameter's value name/description
			--| either field's name for GET,POST, ... variables
			--| or parameters in URI such as foo/{foo}

	description: detachable STRING assign set_description
			-- Description of Current parameters

	type: detachable STRING assign set_type
			-- Expected type of value

feature -- Element change

	set_description (d: like description)
			-- Set `description' to `d'
		do
			description := d
		end

	set_type (t: like type)
			-- Set `type' to `t'
		do
			type := t
		end

note
	copyright: "Copyright (c) 1984-2011, Eiffel Software and others"
	license: "Eiffel Forum License v2 (see http://www.eiffel.com/licensing/forum.txt)"
	source: "[
			Eiffel Software
			5949 Hollister Ave., Goleta, CA 93117 USA
			Telephone 805-685-1006, Fax 805-685-6869
			Website http://www.eiffel.com
			Customer support http://support.eiffel.com
		]"
end
