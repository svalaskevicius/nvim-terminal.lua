--- Highlights terminal CSI ANSI color codes.
-- @module terminal
local nvim = require 'nvim'

local function rgb_to_hex(r, g, b)
  return ("#%02X%02X%02X"):format(r, g, b)
end

local cterm_colors = {
  [0] =
  "#000000",
  "#AA0000",
  "#00AA00",
  "#AA5500",
  "#0000AA",
  "#AA00AA",
  "#00AAAA",
  "#AAAAAA",
  "#555555",
  "#FF5555",
  "#55FF55",
  "#FFFF55",
  "#5555FF",
  "#FF55FF",
  "#55FFFF",
  "#FFFFFF"
}
local function cube6(v)
  return v == 0 and v or (v * 40 + 55)
end
-- https://en.wikipedia.org/wiki/ANSI_escape_code#8-bit
for b = 0, 5 do
  for g = 0, 5 do
    for r = 0, 5 do
      local i = 16 + 36 * r + 6 * g + b
      -- Some terminals implement this differently
      -- cterm_colors[i] = rgb_to_hex(51*r,51*g,51*b)
      cterm_colors[i] = rgb_to_hex(cube6(r), cube6(g), cube6(b))
    end
  end
end
for i = 0, 23 do
  local v = 8 + (i * 10)
  cterm_colors[232 + i] = rgb_to_hex(v, v, v)
end

--- Return a lookup table from [0,255] to an RGB color.
-- Respects g:terminal_color_n
-- @treturn {[number]=string} number to hex string
local function initialize_terminal_colors()
  local result = {}
  for i = 0, 255 do
    result[i] = cterm_colors[i]
  end
  -- g:terminal_color_n overrides
  if nvim.o.termguicolors then
    -- TODO only do 16 colors?
    for i = 0, 255 do
      local status, value = pcall(vim.api.nvim_get_var, 'terminal_color_' .. i)
      if status then
        result[i] = value
      else
        -- TODO assume contiguous and break early?
        break
      end
    end
  end
  return result
end

--- Parses a list of codes into an object of cterm/gui attributes
-- @tparam {[number]=string} rgb_color_table cterm color RGB lookup table
-- @tparam {string|int,...} attrs the list of codes numbers like 0 from ^[[0m
-- @tparam[opt={}] {[string]=string} attributes mutable table to output results into
-- @treturn {[string]=string} a table of cterm*/gui* attributes
local function resolve_attributes(rgb_color_table, attrs, attributes)
  attributes = attributes or {}
  for _, v in ipairs(attrs) do
    local code = tonumber(v)
    if not code then
      -- TODO print warning here? It might be spammy.
      -- nvim.err_writeln("Invalid mode encountered")
    elseif code >= 30 and code <= 37 then
      -- Foreground color (standard colors)
      local ctermfg = code - 30
      attributes.ctermfg = ctermfg
      attributes.guifg = rgb_color_table[ctermfg]
    elseif code >= 40 and code <= 47 then
      -- Background color (standard colors)
      local ctermbg = code - 40
      attributes.ctermbg = ctermbg
      attributes.guibg = rgb_color_table[ctermbg]
    elseif code >= 90 and code <= 97 then
      -- Bright foreground colors
      local ctermfg = code - 90 + 8
      attributes.ctermfg = ctermfg
      attributes.guifg = rgb_color_table[ctermfg]
    elseif code >= 100 and code <= 107 then
      -- Bright background colors
      local ctermbg = code - 100 + 8
      attributes.ctermbg = ctermbg
      attributes.guibg = rgb_color_table[ctermbg]
    elseif code == 22 then
      -- Normal weight (non-bold)
      attributes.cterm = 'NONE'
      attributes.gui = 'NONE'
    elseif code == 39 then
      -- Reset foreground color
      attributes.ctermfg = 'NONE'
      attributes.guifg = 'NONE'
    elseif code == 49 then
      -- Reset background color
      attributes.ctermbg = 'NONE'
      attributes.guibg = 'NONE'
    elseif code == 1 then
      -- Bold
      attributes.cterm = 'bold'
      attributes.gui = 'bold'
    elseif code == 2 then
      -- Dim
      attributes.cterm = 'dim'
      attributes.gui = 'dim'
    elseif code == 3 then
      -- Italic
      attributes.cterm = 'italic'
      attributes.gui = 'italic'
    elseif code == 4 then
      -- Underline
      attributes.cterm = 'underline'
      attributes.gui = 'underline'
    elseif code == 5 then
      -- Blink
      attributes.cterm = 'blink'
      attributes.gui = 'blink'
    elseif code == 7 then
      -- Inverse
      attributes.cterm = 'reverse'
      attributes.gui = 'reverse'
    elseif code == 0 then
      -- Reset all attributes
      for k in pairs(attributes) do
        attributes[k] = nil
      end
    end
  end
  return attributes
end

local function format_attributes(attributes)
  local result = {}
  for k, v in pairs(attributes) do
    table.insert(result, k .. "=" .. v)
  end
  return result
end

local HIGHLIGHT_NAME_PREFIX = "termcolorcode"

--- Make a deterministic name for a highlight given these attributes
local function make_highlight_name(attributes)
  local result = { HIGHLIGHT_NAME_PREFIX }

  -- Sort keys to ensure consistent naming
  local sorted_keys = {}
  for k in pairs(attributes) do
    table.insert(sorted_keys, k)
  end
  table.sort(sorted_keys)

  for _, k in ipairs(sorted_keys) do
    local v = attributes[k]
    if k == "cterm" then
      table.insert(result, "c")
      table.insert(result, v)
    elseif k == "ctermfg" then
      table.insert(result, "cfg")
      table.insert(result, v)
    elseif k == "ctermbg" then
      table.insert(result, "cbg")
      table.insert(result, v)
    elseif k == "gui" then
      table.insert(result, "g")
      table.insert(result, v)
    elseif k == "guifg" then
      table.insert(result, "gfg")
      table.insert(result, (v:gsub("^#", "")))
    elseif k == "guibg" then
      table.insert(result, "gbg")
      table.insert(result, (v:gsub("^#", "")))
    end
  end
  return table.concat(result, "_")
end

local highlight_cache = {}

-- Ref: https://stackoverflow.com/questions/1252539/most-efficient-way-to-determine-if-a-lua-table-is-empty-contains-no-entries
local function table_is_empty(t)
  return next(t) == nil
end

local function create_highlight(attributes)
  if table_is_empty(attributes) then
    return "Normal"
  end

  local highlight_name = make_highlight_name(attributes)

  -- Look up in our cache.
  if not highlight_cache[highlight_name] then
    -- Create the highlight
    nvim.ex.highlight(highlight_name, unpack(format_attributes(attributes)))
    highlight_cache[highlight_name] = true
  end

  return highlight_name
end

--- Highlight a region in a buffer from the attributes specified
local function highlight_from_attributes(buf, ns, current_attributes,
                                         region_line_start, region_byte_start,
                                         region_line_end, region_byte_end)
  local highlight_name = create_highlight(current_attributes)

  if region_line_start == region_line_end then
    nvim.buf_add_highlight(buf, ns, highlight_name, region_line_start, region_byte_start, region_byte_end)
  else
    -- Handle multi-line highlighting
    nvim.buf_add_highlight(buf, ns, highlight_name, region_line_start, region_byte_start, -1)
    for linenum = region_line_start + 1, region_line_end - 1 do
      nvim.buf_add_highlight(buf, ns, highlight_name, linenum, 0, -1)
    end
    nvim.buf_add_highlight(buf, ns, highlight_name, region_line_end, 0, region_byte_end)
  end
end

--- Parse a color code inner
-- Either an RGB code or an incremental list of other CSI codes.
local function parse_color_code(rgb_color_table, code, current_attributes)
  -- Handle empty code (equivalent to reset)
  if #code == 0 then
    return {}
  end

  local attrs = {}
  local start = 1

  while start <= #code do
    local semicolon_pos = code:find(";", start, true)
    local segment

    if semicolon_pos then
      segment = code:sub(start, semicolon_pos - 1)
      start = semicolon_pos + 1
    else
      segment = code:sub(start)
      start = #code + 1
    end

    -- Handle extended color codes (38/48 with 2/5)
    if segment == "38" or segment == "48" then
      local is_foreground = segment == "38"

      -- Check for 256-color mode (38;5;NNN or 38:5:NNN)
      local color_mode = code:sub(start, start + 2)
      if color_mode == ";5;" or color_mode == ":5:" then
        local color_segment = code:sub(start + 3):match("^%d+")
        if color_segment then
          local ctermnr = tonumber(color_segment)
          if ctermnr and ctermnr <= 255 then
            if is_foreground then
              current_attributes.ctermfg = ctermnr
              current_attributes.guifg = rgb_color_table[ctermnr]
            else
              current_attributes.ctermbg = ctermnr
              current_attributes.guibg = rgb_color_table[ctermnr]
            end
          end
          -- Skip past this segment
          start = start + 3 + #color_segment
        end
      elseif color_mode == ";2;" or color_mode == ":2:" then
        -- RGB mode (38;2;R;G;B)
        local separator = color_mode:sub(1, 1)
        local r, g, b = code:sub(start + 3):match("^(%d+)" .. separator .. "(%d+)" .. separator .. "(%d+)")
        if r and g and b then
          r, g, b = tonumber(r), tonumber(g), tonumber(b)
          if r <= 255 and g <= 255 and b <= 255 then
            local hex_color = rgb_to_hex(r, g, b)
            if is_foreground then
              current_attributes.guifg = hex_color
            else
              current_attributes.guibg = hex_color
            end
          end
          -- Skip past this segment (including the trailing separator)
          start = start + 3 + #r + #g + #b + 2           -- +2 for separators
        end
      else
        -- Invalid color mode, skip
        break
      end
    else
      table.insert(attrs, segment)
    end
  end

  if #attrs > 0 then
    resolve_attributes(rgb_color_table, attrs, current_attributes)
  end

  return current_attributes
end

--- Default namespace used in `highlight_buffer` and `attach_to_buffer`.
-- The name is "terminal_highlight"
-- @see highlight_buffer
-- @see attach_to_buffer
local DEFAULT_NAMESPACE = nvim.create_namespace 'terminal_highlight'

--[[-- Highlight the buffer region.
Highlight starting from `line_start` (0-indexed) for each line described by `lines` in the
buffer `buf` and attach it to the namespace `ns`.

@usage
-- Re-highlights the current buffer
local terminal = require 'terminal'
-- Clear existing highlight
vim.api.nvim_buf_clear_namespace(buf, terminal.DEFAULT_NAMESPACE, 0, -1)
local lines = vim.api.nvim_buf_get_lines(0, 0, -1, false)
terminal.highlight_buffer(0, nil, lines, 0)

@usage
local function rehighlight_region(buf, line_start, line_end)
  local ns = terminal.DEFAULT_NAMESPACE
  vim.api.nvim_buf_clear_namespace(buf, ns, line_start, line_end)
  local lines = vim.api.nvim_buf_get_lines(0, line_start, line_end, false)
  terminal.highlight_buffer(0, nil, lines, line_start)
end

@tparam integer buf buffer id.
@tparam[opt=DEFAULT_NAMESPACE] integer ns the namespace id. Create it with `vim.api.create_namespace`
@tparam {string,...} lines the lines to highlight from the buffer.
@tparam integer line_start should be 0-indexed
@tparam[opt=initialize_terminal_colors()] {[number]=string} rgb_color_table cterm color RGB lookup table
]]
local function highlight_buffer(buf, ns, lines, line_start, rgb_color_table)
  rgb_color_table = rgb_color_table or initialize_terminal_colors()
  ns = ns or DEFAULT_NAMESPACE
  --[[
	Algorithm overview:
	Maintain an attributes object which contains the currently applicable
	style to apply based on the incremental definitions from CSI codes.

	1. Start with a bare attributes object which represents a Normal style.
	2. Scan for the next CSI color code.
	3. Apply a highlight on the region between the last CSI code and this new
	one. based on the current attributes.
	4. Update the current attributes with those defined by the new CSI code.
	5. Repeat from 2
	]]
  local current_region_start, current_attributes = nil, {}
  for current_linenum, line in ipairs(lines) do
    -- @todo it's possible to skip processing the new code if the attributes hasn't changed.
    current_linenum = current_linenum - 1 + line_start
    -- Scan for potential color codes.
    for match_start, code, match_end in line:gmatch("()%[([%d;:]*)m()") do
      -- Highlight any current region.
      if current_region_start then
        highlight_from_attributes(buf, ns, current_attributes,
          current_region_start[1], current_region_start[2],
          current_linenum, match_start)
      end
      current_region_start = { current_linenum, match_start }
      -- Update attributes from the new escape code.
      current_attributes = parse_color_code(rgb_color_table, code, current_attributes) or current_attributes
    end
  end
  if current_region_start then
    highlight_from_attributes(buf, ns, current_attributes,
      current_region_start[1], current_region_start[2],
      line_start + #lines, -1)
  end
end

--- Attach to a buffer and continuously highlight changes.
-- @tparam integer buf A value of 0 implies the current buffer.
-- @tparam[opt=initialize_terminal_colors()] {[number]=string} rgb_color_table cterm color RGB lookup table
-- @see highlight_buffer
local function attach_to_buffer(buf, rgb_color_table)
  rgb_color_table = rgb_color_table or initialize_terminal_colors()
  local ns = DEFAULT_NAMESPACE
  --	local ns = nvim.create_namespace 'terminal_highlight'
  do
    nvim.buf_clear_namespace(buf, ns, 0, -1)
    local lines = nvim.buf_get_lines(buf, 0, -1, true)
    highlight_buffer(buf, ns, lines, 0)
  end
  -- send_buffer: true doesn't actually do anything in Lua (yet)
  nvim.buf_attach(buf, false, {
    on_lines = function(event_type, buf, changed_tick, firstline, lastline, new_lastline)
      -- TODO I don't think there's a way around this. Codes are affected by
      -- everything before and affect things after. You could do more
      -- intelligence analysis by only parsing up until the last affected
      -- values, but that's complicated.
      firstline = 0
      new_lastline = -1
      nvim.buf_clear_namespace(buf, ns, firstline, new_lastline)
      local lines = nvim.buf_get_lines(buf, firstline, new_lastline, true)
      highlight_buffer(buf, ns, lines, firstline)
    end,
  })
end

--- Easy to use function if you want the full setup without fine grained control.
-- Establishes an autocmd for `FileType terminal`
-- @tparam[opt=initialize_terminal_colors()] {[number]=string} rgb_color_table cterm color RGB lookup table
-- @usage require'terminal'.setup()
local function setup(rgb_color_table)
  rgb_color_table = rgb_color_table or initialize_terminal_colors()
  function TERMINAL_SETUP_HOOK()
    nvim.win_set_option(0, 'conceallevel', 2)
    nvim.win_set_option(0, 'wrap', false)
    attach_to_buffer(nvim.get_current_buf(), rgb_color_table)
  end

  nvim.ex.augroup("TerminalSetup")
  nvim.ex.autocmd_()
  nvim.ex.autocmd("FileType terminal lua TERMINAL_SETUP_HOOK()")
  nvim.ex.augroup("END")
end

local function test_parse()
  local function assert_eq(a, b, message)
    local result = a == b
    if not result then
      assert(false, (message or "") .. ("%s != %s"):format(vim.inspect(a), vim.inspect(b)))
    end
  end
  local rgb_color_table = initialize_terminal_colors()
  local tests = {
    ["0;38;5;100"] = table_is_empty,
    ["1;33"]       = resolve_attributes(rgb_color_table, { 1, 33 }, {}),
    ["1;38;5;100"] = { cterm = 'bold', ctermfg = 100, guifg = rgb_color_table[100], },
    ["1;38;5;3"]   = resolve_attributes(rgb_color_table, { 1, 33 }, {}),
    ["1;48;5;3"]   = resolve_attributes(rgb_color_table, { 1, 43 }, {}),
    ["30"]         = resolve_attributes(rgb_color_table, { 30 }, {}),
    ["30"]         = resolve_attributes(rgb_color_table, { 30 }, {}),
    ["38;123;432"] = table_is_empty,
    ["38;5;100;0"] = table_is_empty, -- TODO is this really correct?
    ["38;5;100;1"] = { cterm = 'bold', ctermfg = 100, guifg = rgb_color_table[100], },
    ["38;5;100"]   = { ctermfg = 100, guifg = rgb_color_table[100], },
    ["38;5;3"]     = resolve_attributes(rgb_color_table, { 33 }, {}),
    ["38;5;543"]   = table_is_empty,
    ["48;5;100"]   = { ctermbg = 100, guibg = rgb_color_table[100], },
  }
  for r = 0, 355, 100 do
    for g = 0, 355, 100 do
      for b = 0, 355, 100 do
        local key = "38;2;" .. table.concat({ r, g, b }, ';')
        if r > 255 or g > 255 or b > 255 then
          tests[key] = table_is_empty
        else
          tests[key] = { guifg = rgb_to_hex(r, g, b), }
        end
      end
    end
  end

  for input, value in pairs(tests) do
    local result = parse_color_code(rgb_color_table, input, {})
    if type(value) == 'function' then
      assert(result, input)
    elseif type(value) == 'table' then
      local message = ("input=%q: "):format(input)
      assert_eq(type(result), 'table', message)
      for k, v in pairs(value) do
        assert_eq(result[k], v, k .. "=" .. v .. "; " .. message)
      end
    else
      assert_eq(value, result, ("input=%q: "):format(input))
    end
  end
end

--- @export
return {
  DEFAULT_NAMESPACE = DEFAULT_NAMESPACE,
  setup = setup,
  attach_to_buffer = attach_to_buffer,
  highlight_buffer = highlight_buffer,
  initialize_terminal_colors = initialize_terminal_colors,
}

--[=[ Example:
```lua
local buf = 1
local ns = nvim.create_namespace("terminal_highlight")
nvim.buf_clear_namespace(buf, ns, 0, -1)
local lines = nvim.buf_get_lines(buf, 1, -1, false)
require'terminal'.highlight_buffer(buf, ns, lines, 0)
```
]=]
