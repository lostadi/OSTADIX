" Ostadix orchestration with recursively included foreign syntax.
" Source: crates/ostadix-api/src/parser.rs and tools/syntax/languages.json.
" Included language syntaxes supply lexical coloring; O markers retain priority.
if exists('b:current_syntax')
  finish
endif
let s:saved_cpo = &cpo
set cpo&vim
@LANGUAGE_METADATA@
let s:ident = '[A-Za-z_][A-Za-z0-9_]*'
let s:env = '\[\%([0-9]\+\|\*\)\]'
let s:entry = s:ident . '\%(=\%([!-~]\&[^,={}]\)\+\)\?'
let s:attrs = '{[ \t]*' . s:entry . '\%([ \t]*,[ \t]*' . s:entry . '\)*[ \t]*}'
let s:all_tags = []
let b:ostadix_missing_syntax = []
let b:ostadix_fallback_syntax = []
for s:language in s:languages
  call extend(s:all_tags, s:language.tags)
  let s:group = 'ostadixBlock_' . s:language.key
  let s:cluster = 'Ostadix_' . s:language.key
  let s:foreign = s:language.syntax
  if s:language.key ==# 'host'
    let s:contents = '@OstadixHost,@OstadixStructure'
  elseif empty(s:foreign)
    let s:contents = '@OstadixStructure'
  else
    if empty(globpath(&runtimepath, 'syntax/' . s:foreign . '.vim')) && s:foreign ==# 'racket'
      let s:foreign = 'scheme'
      call add(b:ostadix_fallback_syntax, 'racket: Scheme lexical syntax')
    endif
    if !empty(globpath(&runtimepath, 'syntax/' . s:foreign . '.vim'))
      unlet! b:current_syntax
      execute 'syntax include @' . s:cluster . ' syntax/' . s:foreign . '.vim'
      unlet! b:current_syntax
    else
      call add(b:ostadix_missing_syntax, s:language.syntax)
      let s:fallback = 'OstadixFallback_' . s:language.key
      execute 'syntax cluster ' . s:cluster . ' contains=' . s:fallback . ',' . s:fallback . 'Number,' . s:fallback . 'String'
      if !empty(s:language.keywords)
        execute 'syntax keyword ' . s:fallback . ' ' . s:language.keywords . ' contained'
      endif
      execute 'highlight default link ' . s:fallback . ' Keyword'
      execute 'syntax match ' . s:fallback . 'Number /\<[0-9]\+\%([.][0-9]\+\)\?\>/ contained'
      execute 'syntax region ' . s:fallback . 'String start=+"+ skip=+\\.+ end=+"+ contained'
      execute 'highlight default link ' . s:fallback . 'Number Number'
      execute 'highlight default link ' . s:fallback . 'String String'
    endif
    let s:contents = '@' . s:cluster . ',@OstadixStructure'
  endif
  let s:language.contents = s:contents
endfor
" Explicit group IDs span all :syntax include namespaces. ALL/ALLBUT alone
" would only admit the current namespace and miss imported strings/comments.
let s:foreign_groups = {}
for s:line in split(execute('syntax list'), "\n")
  let s:name = matchstr(s:line, '^\h\w*\ze\s\+xxx')
  if !empty(s:name) && s:name !~# '^ostadix'
    let s:foreign_groups[s:name] = 1
  endif
endfor
execute 'syntax cluster OstadixForeignContainers contains=' . (empty(s:foreign_groups) ? 'NONE' : join(keys(s:foreign_groups), ','))
syntax case match
syntax cluster OstadixStructure contains=ostadixSplice,ostadixEscape
syntax cluster OstadixHost contains=ostadixComment,ostadixLet,ostadixFunction,ostadixPunctuation
syntax match ostadixComment /#.*$/
syntax match ostadixLet /\<let\>/
syntax match ostadixFunction /[A-Za-z_][A-Za-z0-9_]*\ze(/
syntax match ostadixPunctuation /[=,()]/
for s:language in s:languages
  let s:group = 'ostadixBlock_' . s:language.key
  let s:contents = s:language.contents
  let s:tags = '\%(' . join(s:language.tags, '\|') . '\)'
  for s:form in ['attrs', 'env', 'bare']
    if s:form ==# 'attrs'
      let s:header = s:tags . '\%(' . s:env . '\)\?' . s:attrs
      let s:guard = ''
    elseif s:form ==# 'env'
      let s:header = s:tags . s:env
      let s:guard = '{\@!'
    else
      let s:header = s:tags
      let s:guard = '[A-Za-z0-9_\[{]\@!'
    endif
    execute 'syntax region ' . s:group . ' matchgroup=ostadixDelimiter start=+\z(' . s:header . '\)\^(+ end=+)_\z1' . s:guard . '+ contains=' . s:contents . ' containedin=@OstadixForeignContainers keepend extend'
  endfor
  execute 'syntax cluster OstadixStructure add=' . s:group
endfor
let s:header = '\%(' . join(s:all_tags, '\|') . '\)\%(' . s:env . '\)\?\%(' . s:attrs . '\)\?'
execute 'syntax match ostadixEscape +\\\%(' . s:header . '\^(\|)_' . s:header . '\|\$\)+ containedin=@OstadixForeignContainers'
syntax match ostadixSplice /\$[A-Za-z_][A-Za-z0-9_]*/ containedin=@OstadixForeignContainers
highlight default link ostadixDelimiter PreProc
highlight default link ostadixSplice Identifier
highlight default link ostadixEscape SpecialChar
highlight default link ostadixComment Comment
highlight default link ostadixLet Keyword
highlight default link ostadixFunction Function
highlight default link ostadixPunctuation Delimiter
syntax sync fromstart
let b:current_syntax = 'ostadix'
let &cpo = s:saved_cpo
unlet s:saved_cpo
