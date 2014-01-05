note
	description: "Summary description for {WSF_BUTTON_CONTROL}."
	author: ""
	date: "$Date$"
	revision: "$Revision$"

class
	WSF_BUTTON_CONTROL

inherit

	WSF_CONTROL
		rename
			make as make_control
		end

create
	make

feature {NONE} -- Initialization

	make (a_text: STRING)
			-- Initialize with specified control name and text
		do
			make_control ("button")
			add_class ("btn")
			add_class ("btn-default")
			text := a_text
		end

feature {WSF_PAGE_CONTROL, WSF_CONTROL} -- State management

	set_state (new_state: JSON_OBJECT)
			-- Restore text from json
		do
			if attached {JSON_STRING} new_state.item ("text") as new_text then
				text := new_text.unescaped_string_32
			end
		end

	state: WSF_JSON_OBJECT
			-- Return state which contains the current text and if there is an event handle attached
		do
			create Result.make
			Result.put_string (text, "text")
			Result.put_boolean (disabled, "disabled")
			Result.put_boolean (attached click_event, "callback_click")
		end

feature --Event handling

	set_click_event (e: attached like click_event)
			-- Set button click event handle
		do
			click_event := e
		end

	handle_callback (cname: LIST [STRING]; event: STRING; event_parameter: detachable ANY)
		do
			if Current.control_name.same_string (cname [1]) and attached click_event as cevent then
				cevent.call (Void)
			end
		end

feature -- Rendering

	render: STRING
			-- HTML representation of this control
		local
			attr: STRING
		do
			create attr.make_empty
			if attached attributes as a then
				attr.append (a)
			end
			if disabled then
				attr.append ("disabled=%"disabled%" ")
			end
			Result := render_tag (text, attr)
		end

feature -- Change

	set_text (t: STRING)
			-- Set text of that button
		do
			if not t.same_string (text) then
				text := t
				state_changes.replace_with_string (text, "text")
			end
		end

	set_disabled (b: BOOLEAN)
		do
			if disabled /= b then
				disabled := b
				state_changes.replace_with_boolean (disabled, "disabled")
			end
		end

feature -- Properties

	disabled: BOOLEAN
			-- Defines if the button is editable

	text: STRING
			-- The text currently displayed on this button

	click_event: detachable PROCEDURE [ANY, TUPLE]
			-- Event that is executed when button is clicked

end