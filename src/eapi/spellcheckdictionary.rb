# A part of Elten - EltenLink / Elten Network desktop client.
# Copyright (C) 2014-2026 Dawid Pieper
# Elten is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3. 
# Elten is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. 
# You should have received a copy of the GNU General Public License along with Elten. If not, see <https://www.gnu.org/licenses/>. 

module EltenAPI
  module SpellCheckDictionary
    KEY = "SpellCheckCustomWords"
    LEGACY_REGEXP_KEY = "SpellCheckCustomRegexps"
    TYPES = ["w", "a", "r"].freeze

    class Entry
      attr_reader :pattern, :type, :case_sensitive

      def initialize(pattern, type, case_sensitive)
        @pattern = pattern.to_s
        @type = TYPES.include?(type.to_s) ? type.to_s : "w"
        @case_sensitive = case_sensitive == true
      end

      def match_type
        TYPES.index(@type)
      end

      def serialize
        (@case_sensitive ? "0" : "1") + @type + "|" + @pattern
      end

      def type_label
        case @type
        when "a" then p_("SpellCheckDictionary", "Match anywhere")
        when "r" then p_("SpellCheckDictionary", "Regular expression")
        else p_("SpellCheckDictionary", "Whole word")
        end
      end

      def case_label
        @case_sensitive ? p_("SpellCheckDictionary", "Yes") : p_("SpellCheckDictionary", "No")
      end

      def matches?(word)
        return false if @pattern == ""
        case @type
        when "a"
          @case_sensitive ? word.include?(@pattern) : word.downcase.include?(@pattern.downcase)
        when "r"
          begin
            (@case_sensitive ? Regexp.new(@pattern) : Regexp.new(@pattern, Regexp::IGNORECASE)).match?(word)
          rescue Exception
            false
          end
        else
          @case_sensitive ? @pattern == word : @pattern.casecmp?(word)
        end
      end
    end

    class << self
      def entries
        LocalConfig[KEY, [], type: :array_of_strings].map { |entry| parse(entry, "w") } +
          LocalConfig[LEGACY_REGEXP_KEY, [], type: :array_of_strings].map { |entry| parse(entry, "r") }
      end

      def parse(entry, default_type = "w")
        entry = entry.to_s
        if entry =~ /\A([01])([war])\|(.*)\z/m
          Entry.new($3, $2, $1 == "0")
        elsif entry =~ /\A([01])\|(.*)\z/m
          Entry.new($2, default_type, $1 == "0")
        else
          Entry.new(entry, default_type, false)
        end
      end

      def add(pattern, match_type: 0, case_sensitive: false)
        entry = build(pattern, match_type, case_sensitive)
        return entry if entry.is_a?(Symbol)
        return :duplicate if duplicate?(entry.serialize)
        LocalConfig[KEY] = LocalConfig[KEY, [], type: :array_of_strings].push(entry.serialize)
        :added
      end

      def replace(index, pattern, match_type: 0, case_sensitive: false)
        entry = build(pattern, match_type, case_sensitive)
        return entry if entry.is_a?(Symbol)
        index = index.to_i
        key, position = locate(index)
        return :missing if key == nil
        list = LocalConfig[key, [], type: :array_of_strings]
        return :saved if parse(list[position], key == KEY ? "w" : "r").serialize == entry.serialize
        return :duplicate if duplicate?(entry.serialize, index)
        list[position] = entry.serialize
        LocalConfig[key] = list
        :saved
      end

      def delete(index)
        key, position = locate(index)
        return false if key == nil
        list = LocalConfig[key, [], type: :array_of_strings]
        list.delete_at(position)
        LocalConfig[key] = list
        true
      end

      def match?(word)
        word = word.to_s
        return false if word == ""
        entries.any? { |entry| entry.matches?(word) }
      end

      private

      def locate(index)
        index = index.to_i
        return [nil, nil] if index < 0
        primary = LocalConfig[KEY, [], type: :array_of_strings].size
        return [KEY, index] if index < primary
        index -= primary
        index < LocalConfig[LEGACY_REGEXP_KEY, [], type: :array_of_strings].size ? [LEGACY_REGEXP_KEY, index] : [nil, nil]
      end

      def duplicate?(serialized, except = nil)
        entries.each_with_index.any? { |entry, i| entry.serialize == serialized && i != except }
      end

      def build(pattern, match_type, case_sensitive)
        type = TYPES[match_type.to_i] || "w"
        pattern = pattern.to_s
        pattern = pattern.strip if type != "r"
        return :empty if pattern == ""
        if type == "r"
          begin
            Regexp.new(pattern)
          rescue Exception
            return :invalid
          end
        end
        Entry.new(pattern, type, case_sensitive == true)
      end
    end
  end
end
