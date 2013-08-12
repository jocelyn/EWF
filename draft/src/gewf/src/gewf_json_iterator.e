note
	description: "Summary description for {GEWF_JSON_ITERATOR}."
	author: ""
	date: "$Date$"
	revision: "$Revision$"

class
	GEWF_JSON_ITERATOR

inherit
	JSON_VISITOR
		rename
			print as std_print
		end

	LOCALIZED_PRINTER
		rename
			print as std_print,
			localized_print as print
		end

create
	make

feature -- Initialization

	make (ht: STRING_TABLE [READABLE_STRING_32])
		do
			create location.make (3)
			variables := ht
		end

	location: ARRAYED_LIST [JSON_STRING]

	variables: STRING_TABLE [READABLE_STRING_32]

feature -- Visitor Pattern

	visit_json_array (a_json_array: JSON_ARRAY)
			-- Visit `a_json_array'.
		do
			across
				a_json_array.array_representation as c
			loop
				c.item.accept (Current)
			end
		end

	visit_json_boolean (a_json_boolean: JSON_BOOLEAN)
			-- Visit `a_json_boolean'.
		do
		end

	visit_json_null (a_json_null: JSON_NULL)
			-- Visit `a_json_null'.
		do
		end

	visit_json_number (a_json_number: JSON_NUMBER)
			-- Visit `a_json_number'.
		do
		end

	visit_json_object (a_json_object: JSON_OBJECT)
			-- Visit `a_json_object'.
		local
			jv: JSON_VALUE
			jk,k: JSON_STRING
			l_prompt, l_default: detachable READABLE_STRING_32
			l_value: READABLE_STRING_32
			s: STRING_32
			l_to_remove: ARRAYED_LIST [JSON_STRING]
		do
			create l_to_remove.make (0)
			across
				a_json_object as c
			loop
				jv := c.item
				jk := c.key
				if
					jk.unescaped_string_32.has ('.')
				then
					l_to_remove.force (jk)
				elseif
					attached {JSON_STRING} jv as js and then
					attached js.unescaped_string_32 as s32 and then
					s32.has_substring ("$")
				then
					-- maybe user input required
					create k.make_json_from_string_32 (jk.unescaped_string_32 + {STRING_32} ".prompt")
					if attached {JSON_STRING} a_json_object.item (k) as j_prompt then
						l_prompt := j_prompt.unescaped_string_32
					else
						create s.make_empty
						across
							location as l
						loop
							if not s.is_empty then
								s.append_character ('.')
							end
							s.append (l.item.unescaped_string_32)
						end
						l_prompt := {STRING_32} "Value for " + s + " ?"
					end
					create k.make_json_from_string_32 (jk.unescaped_string_32 + {STRING_32} ".default")
					if attached {JSON_STRING} a_json_object.item (k) as j_default then
						l_default := j_default.unescaped_string_32
					else
						l_default := Void
					end
					if l_prompt /= Void then
						print (l_prompt)
						if l_default /= Void then
							print ("(default: ")
							print (l_default)
							print (")")
						end
						if not s32.same_string_general ("$$") then
							print (" [ -> ")
							print (s32)
							print (" ] ")
						end
						print (" ? ")
						io.read_line
						l_value := io.last_string
						if l_value.is_empty and l_default /= Void then
							l_value := l_default.string
						end
						if s32.same_string_general ("$$") then
							a_json_object.replace (create {JSON_STRING}.make_json_from_string_32 (l_value), jk)
						else
							a_json_object.replace (create {JSON_STRING}.make_json_from_string_32 (l_value), jk)
							variables.force (l_value, s32.tail (s32.count - 1))
						end
					end
				end
				location.force (jk)
				jv.accept (Current)
				location.finish
				location.remove
			end
			across
				l_to_remove as c
			loop
				a_json_object.remove (c.item)
			end
		end

    visit_json_string (a_json_string: JSON_STRING)
			-- Visit `a_json_string'.
		do
		end

note
	copyright: "2011-2013, Jocelyn Fiat, Javier Velilla, Olivier Ligot, Eiffel Software and others"
	license: "Eiffel Forum License v2 (see http://www.eiffel.com/licensing/forum.txt)"
	source: "[
			Eiffel Software
			5949 Hollister Ave., Goleta, CA 93117 USA
			Telephone 805-685-1006, Fax 805-685-6869
			Website http://www.eiffel.com
			Customer support http://support.eiffel.com
		]"
end
