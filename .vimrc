execute pathogen#infect()
set encoding=utf-8
syntax on
set bg=dark

" setlocal spell spelllang=en_us

" autocmd BufWritePre *.py execute ':Black'

set nofoldenable    " disable folding
set nohlsearch
set tw=80
" 80 characters line
set colorcolumn=81
highlight ColorColumn ctermbg=Grey ctermfg=DarkRed
" Highlight trailing spaces
" http://vim.wikia.com/wiki/Highlight_unwanted_spaces
highlight ExtraWhitespace ctermbg=red guibg=red
match ExtraWhitespace /\s\+$/
autocmd BufWinEnter * match ExtraWhitespace /\s\+$/
autocmd InsertEnter * match ExtraWhitespace /\s\+\%#\@<!$/
autocmd InsertLeave * match ExtraWhitespace /\s\+$/
autocmd BufWinLeave * call clearmatches()

filetype plugin indent on
" show existing tab with 2 spaces width
set tabstop=2
" when indenting with '>', use 2 spaces width
set shiftwidth=2
" On pressing tab, insert 2 spaces
set expandtab
set modeline
set softtabstop=2
" set bg=dark

let dart_format_on_save=1
let dart_html_in_string=v:true
let dart_style_guide=2

autocmd Filetype ruby setlocal ts=2 sts=2 sw=2
autocmd Filetype html setlocal ts=2 sts=2 sw=2
autocmd Filetype javascript setlocal ts=2 sts=2 sw=2
autocmd Filetype yaml setlocal ts=2 sts=2 sw=2
autocmd Filetype c setlocal ts=4 sts=4 sw=4

" More copy paste lines
set viminfo='20,<1000

let g:syntastic_python_checkers = ['mypy']
" set statusline+=%#warningmsg#
" set statusline+=%{SyntasticStatuslineFlag()}
" set statusline+=%*
let g:syntastic_always_populate_loc_list = 1
let g:syntastic_auto_loc_list = 1
let g:syntastic_check_on_open = 1
let g:syntastic_check_on_wq = 0
let g:syntastic_python_mypy_args = '--ignore-missing-imports'

autocmd BufEnter * set mouse=

set nobackup
set nowritebackup
silent! so .vimlocal
