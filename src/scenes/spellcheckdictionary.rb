# A part of Elten - EltenLink / Elten Network desktop client.
# Copyright (C) 2014-2026 Dawid Pieper
# Elten is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3. 
# Elten is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. 
# You should have received a copy of the GNU General Public License along with Elten. If not, see <https://www.gnu.org/licenses/>. 

class Scene_SpellCheckDictionary
  def main
    @entries=SpellCheckDictionary.entries
    @field=[]
    @field[0]=TableBox.new([p_("SpellCheckDictionary", "Pattern"), p_("SpellCheckDictionary", "Match type"), p_("SpellCheckDictionary", "Case sensitive")], rows, header: p_("SpellCheckDictionary", "Dictionary entries"), quiet: false, empty_label: p_("SpellCheckDictionary", "The dictionary is empty"))
    @field[1]=Button.new(p_("SpellCheckDictionary", "Add"))
    @field[2]=Button.new(p_("SpellCheckDictionary", "Edit"))
    @field[3]=Button.new(p_("SpellCheckDictionary", "Delete"))
    @field[4]=Button.new(_("Close"))
    @form=Form.new(@field)
    @form.bind_context{|menu|context(menu)}
    toggle_buttons
    loop do
      loop_update
      @form.update
      if key_pressed?(:key_escape) or @field[4].pressed?
        $scene=Scene_Main.new
        break
      end
      add_entry if @field[1].pressed?
      edit_entry(@field[0].index) if (@form.index==0 and @field[0].selected?) or @field[2].pressed?
      delete_entry(@field[0].index) if @field[3].pressed?
      break if $scene!=self
    end
  end
  def context(menu)
    menu.option(p_("SpellCheckDictionary", "Add entry"), nil, "n") {add_entry}
    if @entries.size>0
      menu.option(p_("SpellCheckDictionary", "Edit entry"), nil, "e") {edit_entry(@field[0].index)}
      menu.option(p_("SpellCheckDictionary", "Delete entry"), nil, :del) {delete_entry(@field[0].index)}
    end
  end
  def add_entry
    refresh if entry_dialog
    focus_list
  end
  def edit_entry(index)
    return if index<0 or @entries[index]==nil
    refresh if entry_dialog(@entries[index], index)
    focus_list
  end
  def delete_entry(index)
    return if index<0
    entry=@entries[index]
    return if entry==nil
    if confirm(p_("SpellCheckDictionary", "Are you sure you want to delete this entry?")+"\r\n"+entry.pattern) and SpellCheckDictionary.delete(index)
      refresh
      play_sound("editbox_delete")
    end
    focus_list
  end
  def entry_dialog(entry=nil, index=nil)
    saved=false
    begin
      dialog_open
      loop_update
      dform=Form.new([
        dpat=EditBox.new(p_("SpellCheckDictionary", "Pattern"), type: 0, text: (entry!=nil) ? entry.pattern : "", quiet: true),
        dtype=ListBox.new([p_("SpellCheckDictionary", "Whole word"), p_("SpellCheckDictionary", "Match anywhere"), p_("SpellCheckDictionary", "Regular expression")], header: p_("SpellCheckDictionary", "Match type"), index: (entry!=nil) ? entry.match_type : 0),
        dcase=CheckBox.new(p_("SpellCheckDictionary", "Case sensitive"), checked: (entry!=nil) ? entry.case_sensitive : false),
        btn_save=Button.new(_("Save")),
        btn_cancel=Button.new(_("Cancel"))
      ], index: 0, silent: false, quiet: true)
      dform.cancel_button=btn_cancel
      btn_cancel.on(:press) {dform.resume}
      btn_save.on(:press) {
        result=(index!=nil) ? SpellCheckDictionary.replace(index, dpat.text, match_type: dtype.index, case_sensitive: dcase.value) : SpellCheckDictionary.add(dpat.text, match_type: dtype.index, case_sensitive: dcase.value)
        case result
        when :added, :saved
          saved=true
          dform.resume
        when :duplicate
          alert(p_("SpellCheckDictionary", "This entry is already in the dictionary."))
        when :invalid
          alert(p_("SpellCheckDictionary", "Invalid regular expression."))
        when :missing
          alert(p_("SpellCheckDictionary", "This entry is no longer in the dictionary."))
          dform.resume
        when :empty
          alert(p_("SpellCheckDictionary", "Please enter a pattern."))
        end
      }
      dform.accept_button=btn_save
      dform.wait
    ensure
      dialog_close
      loop_update
    end
    saved
  end
  def focus_list
    @form.index=0
    @field[0].focus
  end
  def rows
    @entries.map{|entry|[entry.pattern, entry.type_label, entry.case_label]}
  end
  def toggle_buttons
    [2, 3].each{|i|(@entries.size>0) ? @form.show(i) : @form.hide(i)}
  end
  def refresh
    @entries=SpellCheckDictionary.entries
    index=@field[0].index
    index=@entries.size-1 if index>=@entries.size
    index=0 if index<0
    @field[0].rows=rows
    @field[0].reload
    @field[0].index=index
    toggle_buttons
  end
end
