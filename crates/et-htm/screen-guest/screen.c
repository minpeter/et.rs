/* Canonical 8a306f6 PaneScreen adapter. Runs ONLY in an import-free Wasm guest.
 * ABI v1: offsets/lengths and integers; no native pointers cross into Rust.
 * Libvterm is MIT; this adapter follows et.rs's Apache-2.0 license. */
#include "vterm.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <wasi/api.h>

/* libc's formatting/allocation objects reference these even though the screen
 * has no I/O or clock. Never grant WASI host capabilities to satisfy them. */
__wasi_errno_t __wrap___wasi_fd_close(__wasi_fd_t fd) { (void)fd; __builtin_trap(); }
__wasi_errno_t __wrap___wasi_fd_seek(__wasi_fd_t fd, __wasi_filedelta_t offset,
                            __wasi_whence_t whence, __wasi_filesize_t *result) {
  (void)fd; (void)offset; (void)whence; (void)result; __builtin_trap();
}
__wasi_errno_t __wrap___wasi_fd_write(__wasi_fd_t fd, const __wasi_ciovec_t *iov,
                             size_t count, __wasi_size_t *written) {
  (void)fd; (void)iov; (void)count; (void)written; __builtin_trap();
}
__wasi_errno_t __wrap___wasi_clock_time_get(__wasi_clockid_t clock,
                                   __wasi_timestamp_t precision,
                                   __wasi_timestamp_t *result) {
  (void)clock; (void)precision; *result = 0; return 0;
}

#define EXPORT(name) __attribute__((export_name(name)))
#define HISTORY 2000
#define INPUT_MAX 65536
#define OUTPUT_MAX 131072
static VTerm *vt;
static VTermScreen *screen;
static VTermState *state;
static int cols, rows, alternate, visible = 1, mouse, filter;
static unsigned char input[INPUT_MAX], filtered[INPUT_MAX + 1];
static unsigned char output[OUTPUT_MAX];
static size_t output_len;
static int output_overflow;
static char title[65536];
static size_t title_len;
typedef struct { VTermScreenCell *cells; int cols, continuation; } Line;
static Line history[HISTORY];
static int head, count;

static void *allocate(size_t size, void *unused) {
  (void)unused;
  void *p = calloc(1, size);
  if (!p) __builtin_trap();
  return p;
}
static void release(void *p, void *unused) { (void)unused; free(p); }
static VTermAllocatorFunctions allocator = {allocate, release};
static int damage(VTermRect rect, void *unused) { (void)rect; (void)unused; return 1; }
static int cursor(VTermPos pos, VTermPos old, int on, void *unused) {
  (void)pos; (void)old; (void)unused; visible = on != 0; return 1;
}
static int property(VTermProp prop, VTermValue *val, void *unused) {
  (void)unused;
  switch (prop) {
    case VTERM_PROP_ALTSCREEN: alternate = val->boolean != 0; break;
    case VTERM_PROP_CURSORVISIBLE: visible = val->boolean != 0; break;
    case VTERM_PROP_MOUSE: mouse = val->number; break;
    case VTERM_PROP_TITLE:
      if (val->string.str && val->string.len) {
        if (val->string.initial) title_len = 0;
        if (val->string.len > sizeof(title) - title_len) __builtin_trap();
        memcpy(title + title_len, val->string.str, val->string.len);
        title_len += val->string.len;
      }
      break;
    default: break;
  }
  return 1;
}
static int push4(int n, const VTermScreenCell *cells, bool continuation, void *unused) {
  (void)unused;
  int at;
  if (count == HISTORY) { at = head; head = (head + 1) % HISTORY; free(history[at].cells); }
  else { at = (head + count++) % HISTORY; }
  history[at] = (Line){allocate(sizeof(*cells) * n, NULL), n, continuation};
  memcpy(history[at].cells, cells, sizeof(*cells) * n);
  return 1;
}
static int push(int n, const VTermScreenCell *cells, void *unused) { return push4(n,cells,false,unused); }
static int clear(void *unused) {
  (void)unused;
  for (int i = 0; i < count; i++) free(history[(head+i)%HISTORY].cells);
  head = count = 0; return 1;
}
static const VTermScreenCallbacks callbacks = {
  .damage=damage, .movecursor=cursor, .settermprop=property,
  .sb_pushline=push, .sb_pushline4=push4, .sb_clear=clear
};
EXPORT("init") void init(int width, int height) {
  if (vt || width < 1 || width > 512 || height < 1 || height > 256) __builtin_trap();
  cols=width; rows=height;
  vt=vterm_new_with_allocator(rows,cols,&allocator,NULL);
  vterm_set_utf8(vt,1);
  screen=vterm_obtain_screen(vt); state=vterm_obtain_state(vt);
  vterm_screen_enable_altscreen(screen,1);
  vterm_screen_set_callbacks(screen,&callbacks,NULL);
  vterm_screen_callbacks_has_pushline4(screen);
  vterm_screen_reset(screen,1);
}
EXPORT("input") uintptr_t input_ptr(void) { return (uintptr_t)input; }
EXPORT("feed") void feed(int length) {
  if (length < 0 || length > INPUT_MAX) __builtin_trap();
  size_t n=0;
  for (int i=0;i<length;i++) {
    unsigned char c=input[i];
    switch(filter) {
      case 0: if(c==27) filter=1; else filtered[n++]=c; break;
      case 1:
        if(c=='k') filter=2;
        else { filtered[n++]=27; if(c!=27) { filtered[n++]=c; filter=0; } }
        break;
      case 2: if(c==27) filter=3; else if(c==7) filter=0; break;
      case 3: if(c=='\\') filter=0; else if(c!=27) filter=2; break;
    }
  }
  if(n) vterm_input_write(vt,(const char*)filtered,n);
  vterm_screen_flush_damage(screen);
}
EXPORT("resize") void resize_screen(int width,int height) {
  if(width<1 || width>512 || height<1 || height>256) __builtin_trap();
  cols=width; rows=height; vterm_set_size(vt,rows,cols); vterm_screen_flush_damage(screen);
}
EXPORT("metadata") int metadata(int key) {
  VTermPos pos; vterm_state_get_cursorpos(state,&pos);
  switch(key) { case 0:return pos.col; case 1:return pos.row; case 2:return visible; case 3:return alternate; case 4:return cols; case 5:return rows; case 6:return count; case 7:return mouse; default:return 0; }
}
static void append(const void *data,size_t n) {
  if(n>OUTPUT_MAX-output_len) { output_overflow=1; return; }
  memcpy(output+output_len,data,n); output_len+=n;
}
static void byte(unsigned char c) { append(&c,1); }
static void utf8(uint32_t cp) {
  if(!cp) return;
  if(cp<0x80) byte(cp);
  else if(cp<0x800) { byte(0xc0|(cp>>6)); byte(0x80|(cp&63)); }
  else if(cp<0x10000) { byte(0xe0|(cp>>12)); byte(0x80|((cp>>6)&63)); byte(0x80|(cp&63)); }
  else { byte(0xf0|(cp>>18)); byte(0x80|((cp>>12)&63)); byte(0x80|((cp>>6)&63)); byte(0x80|(cp&63)); }
}
static void sgr(char *buf,const VTermScreenCell *cell) {
  strcpy(buf,"\x1b[0");
  if(cell->attrs.bold) strcat(buf,";1");
  if(cell->attrs.underline) strcat(buf,";4");
  if(cell->attrs.italic) strcat(buf,";3");
  if(cell->attrs.reverse) strcat(buf,";7");
  if(VTERM_COLOR_IS_INDEXED(&cell->fg) && !VTERM_COLOR_IS_DEFAULT_FG(&cell->fg)) {
    int n=cell->fg.indexed.idx;
    if(n<16) sprintf(buf+strlen(buf),";%d",n<8?30+n:90+n-8);
    else sprintf(buf+strlen(buf),";38;5;%d",n);
  }
  if(VTERM_COLOR_IS_INDEXED(&cell->bg) && !VTERM_COLOR_IS_DEFAULT_BG(&cell->bg)) {
    int n=cell->bg.indexed.idx;
    if(n<16) sprintf(buf+strlen(buf),";%d",n<8?40+n:100+n-8);
    else sprintf(buf+strlen(buf),";48;5;%d",n);
  }
  strcat(buf,"m");
}
static void row(int index,int styled,int trailing) {
  Line *hist=index<count?&history[(head+index)%HISTORY]:NULL;
  int width=hist?hist->cols:cols;
  size_t begin=output_len;
  int nonspace=0;
  char last[80]="";
  for(int col=0;col<width;col++) {
    VTermScreenCell cell;
    if(hist) cell=hist->cells[col];
    else vterm_screen_get_cell(screen,(VTermPos){index-count,col},&cell);
    if(styled) { char attr[80]; sgr(attr,&cell); if(strcmp(last,attr)) { append(attr,strlen(attr)); strcpy(last,attr); } }
    if(cell.chars[0]) { utf8(cell.chars[0]); nonspace=1; } else byte(' ');
    if(cell.width>1) col+=cell.width-1;
  }
  if(!trailing) {
    if(nonspace) { while(output_len>begin && output[output_len-1]==' ') output_len--; }
    else output_len=begin;
  }
  if(styled && output_len>begin) append("\x1b[0m",4);
}
EXPORT("capture") int capture(int flags,int start,int end) {
  output_len=0;
  output_overflow=0;
  if((flags&2) && !alternate) return 0;
  int total=count+rows;
  int64_t first=start<0?(int64_t)total+start:(int64_t)count+start;
  int64_t last=end<0?(int64_t)total+end:(int64_t)count+end;
  if(!start && !end) { first=count; last=total-1; }
  if(first<0) first=0;
  if(last>=total) last=total-1;
  for(int64_t i=first;i<=last;i++) {
    int continuation=i<count?history[(head+i)%HISTORY].continuation:vterm_state_get_lineinfo(state,i-count)->continuation;
    if(output_len && (!(flags&4) || !continuation)) byte('\n');
    row(i,flags&1,flags&8);
    if(output_overflow) return -1;
  }
  if(output_len) byte('\n');
  return output_overflow?-1:(int)output_len;
}
EXPORT("output") uintptr_t output_ptr(void) { return (uintptr_t)output; }
EXPORT("title") int get_title(void) { output_len=0; append(title,title_len); return title_len; }
