/* Resident command service for the original 9front ABI.
 * Build ONLY with the admitted original ARM64 tools. This program dispatches
 * original executables; it is neither a shell implementation nor a new grant.
 * One trusted operator owns the pregranted native namespace and this service.
 */
#include <u.h>
#include <libc.h>
#include <libsec.h>

enum {
	Maxrequest = 1048576, Maxargs = 64, Maxpath = 4095,
	Requestheader = 112, Resultheader = 200,
	Timedout = 1, Outtruncated = 2, Errtruncated = 4, Startfailed = 8,
	Cancelled = 16, Interrupted = Timedout|Cancelled,
	Scanmin = 50, Scanmax = 250,
};

typedef struct Request Request;
struct Request {
	uchar *wire;
	long bytes;
	char *cwd;
	char *args[Maxargs+1];
	uchar *input;
	ulong inputbytes, timeout, outlimit, errlimit;
	char id[33];
	uchar digest[32];
};

static char generation[17], instance[33];
static char *servicedir;
typedef struct Accepted Accepted;
struct Accepted { char id[33]; Accepted *next; };
static Accepted *accepted;

static void
fatal(char *message)
{
	fprint(2, "p9cmdsrv: %s: %r\n", message);
	exits(message);
}

static int
hexid(char *s, int n)
{
	int i;
	if(strlen(s) != n) return 0;
	for(i=0; i<n; i++)
		if(!((s[i]>='0' && s[i]<='9') || (s[i]>='a' && s[i]<='f'))) return 0;
	return 1;
}

static void
hex(uchar *input, char *output, int n)
{
	static char alphabet[] = "0123456789abcdef";
	int i;
	for(i=0; i<n; i++){
		output[2*i] = alphabet[input[i]>>4];
		output[2*i+1] = alphabet[input[i]&15];
	}
	output[2*n] = 0;
}

static ulong
get32(uchar *p)
{
	return (ulong)p[0] | (ulong)p[1]<<8 | (ulong)p[2]<<16 | (ulong)p[3]<<24;
}

static void
put32(uchar *p, ulong x)
{
	p[0]=x; p[1]=x>>8; p[2]=x>>16; p[3]=x>>24;
}

static char*
path(char *directory, char *name)
{
	char *p;
	p = smprint("%s/%s", directory, name);
	if(p == nil) fatal("path allocation");
	return p;
}

static int
present(char *directory, char *name)
{
	char *p;
	int yes;
	p=path(directory, name); yes=access(p, AEXIST)==0; free(p);
	return yes;
}

static int
writeall(int fd, void *data, long bytes)
{
	long n;
	uchar *p=data;
	while(bytes > 0){
		n=write(fd, p, bytes);
		if(n<=0) return -1;
		p+=n; bytes-=n;
	}
	return 0;
}

static int
publish(char *directory, char *name, void *data, long bytes)
{
	char *p, *pending;
	Dir rename;
	int fd, ok;
	p=path(directory, name);
	/* A partial marker remains a fail-closed record. Unique paths are never
	 * replaced or replayed, even following a service crash. */
	if(access(p,AEXIST)==0){ free(p); return -1; }
	pending=smprint("%s/.%s.pending.%d",directory,name,getpid());
	if(pending==nil){ free(p); return -1; }
	fd=create(pending, OWRITE, 0644); free(p);
	if(fd<0){ free(pending); return -1; }
	ok=writeall(fd,data,bytes); close(fd);
	if(ok==0){ nulldir(&rename); rename.name=name; ok=dirwstat(pending,&rename); }
	free(pending); return ok;
}

static uchar*
readfile(char *directory, char *name, long limit, long *length)
{
	char *p;
	uchar *data;
	Dir *d;
	int fd;
	long n, total;
	p=path(directory,name); fd=open(p,OREAD); free(p);
	if(fd<0) return nil;
	d=dirfstat(fd);
	if(d==nil || (d->mode&DMDIR) || d->length<0 || d->length>limit){
		free(d); close(fd); return nil;
	}
	data=malloc(d->length+1);
	if(data==nil){ free(d); close(fd); return nil; }
	total=0;
	while(total<d->length){
		n=read(fd,data+total,d->length-total);
		if(n<=0){ free(data); free(d); close(fd); return nil; }
		total+=n;
	}
	/* Capture a complete object, not a prefix of a concurrently growing one. */
	n=read(fd,data+total,1);
	free(d); close(fd);
	if(n!=0){ free(data); return nil; }
	data[total]=0; *length=total; return data;
}

static char*
string(uchar *data, ulong bytes)
{
	char *s, *p, *end;
	Rune rune;
	int n;
	if(memchr(data,0,bytes)!=nil) return nil;
	s=malloc(bytes+1);
	if(s==nil) return nil;
	memmove(s,data,bytes); s[bytes]=0;
	for(p=s,end=s+bytes; p<end; p+=n){
		if(!fullrune(p,end-p)){ free(s); return nil; }
		n=chartorune(&rune,p);
		if((rune==Runeerror && n==1) || (rune>=0xD800 && rune<=0xDFFF)){ free(s); return nil; }
	}
	return s;
}

static void
freerequest(Request *r)
{
	int i;
	for(i=0; i<Maxargs; i++) free(r->args[i]);
	free(r->cwd); free(r->wire); memset(r,0,sizeof *r);
}

static int
parse(Request *r, char *id)
{
	uchar *p, *end;
	ulong argc, cwdbytes, n;
	int i;
	p=r->wire; end=p+r->bytes;
	if(r->bytes<Requestheader || memcmp(p,"OC9REQ01",8)!=0
	|| memcmp(p+8,generation,16)!=0 || memcmp(p+24,instance,32)!=0
	|| memcmp(p+56,id,32)!=0) return -1;
	argc=get32(p+88); cwdbytes=get32(p+92); r->inputbytes=get32(p+96);
	r->timeout=get32(p+100); r->outlimit=get32(p+104); r->errlimit=get32(p+108);
	if(argc<1 || argc>Maxargs || cwdbytes<1 || cwdbytes>Maxpath
	|| r->timeout<1 || r->timeout>300000 || r->outlimit>Maxrequest
	|| r->errlimit>Maxrequest) return -1;
	p+=Requestheader;
	if(cwdbytes>end-p || (r->cwd=string(p,cwdbytes))==nil || r->cwd[0]!='/') return -1;
	p+=cwdbytes;
	for(i=0; i<argc; i++){
		if(end-p<4) return -1;
		n=get32(p); p+=4;
		if(n>65535 || n>end-p || (r->args[i]=string(p,n))==nil) return -1;
		p+=n;
	}
	if(r->args[0][0]!='/' || end-p!=r->inputbytes) return -1;
	r->input=p; memmove(r->id,id,33);
	sha2_256(r->wire,r->bytes,r->digest,nil);
	return 0;
}

static void
closepipes(int pipes[5][2], int keep, int keep2)
{
	int i,j;
	for(i=0;i<5;i++) for(j=0;j<2;j++) if(pipes[i][j]!=keep && pipes[i][j]!=keep2) close(pipes[i][j]);
}

static int
collector(int pipes[5][2], int index, char *directory, char *name, ulong limit)
{
	int pid, fd, overflow;
	long n, amount;
	ulong total;
	uchar buffer[4096];
	char *p;
	pid=rfork(RFPROC|RFFDG);
	if(pid!=0) return pid;
	closepipes(pipes,pipes[index][0],-1);
	p=path(directory,name); fd=create(p,OWRITE,0644); free(p);
	if(fd<0) exits("capture create");
	total=0; overflow=0;
	while((n=read(pipes[index][0],buffer,sizeof buffer))>0){
		amount=n;
		if(amount>limit-total){
			amount=limit-total;
			if(!overflow && publish(directory,index==1 ? ".stdout.truncated" : ".stderr.truncated","1",1)<0)
				exits("capture truncation record");
			overflow=1;
		}
		if(writeall(fd,buffer,amount)<0){ close(fd); exits("capture write"); }
		total+=amount;
	}
	close(fd); close(pipes[index][0]);
	if(n<0) exits("capture read");
	exits(overflow ? "truncated" : nil);
	return -1;
}

static int
feeder(int pipes[5][2], Request *r)
{
	int pid;
	pid=rfork(RFPROC|RFFDG);
	if(pid!=0) return pid;
	closepipes(pipes,pipes[0][1],-1);
	/* A program may legitimately exit without consuming all of its stdin. */
	writeall(pipes[0][1],r->input,r->inputbytes);
	close(pipes[0][1]); exits(nil); return -1;
}

/* The supervisor remains the live note-group anchor while descendants or
 * collectors exist. The raw wait string belongs to the actual executable,
 * not this wrapper. A private close-on-exec channel distinguishes setup
 * failure from a program that legitimately exits with the text "exec". */
static int
job(int pipes[5][2], Request *r)
{
	int pid, child, launch[2], fd, failure;
	uchar header[8], byte;
	char name[64];
	Waitmsg *w;
	pid=rfork(RFPROC|RFFDG|RFENVG|RFNAMEG|RFNOTEG|RFREND);
	if(pid!=0) return pid;
	if(pipe(launch)<0) exits("supervisor pipe");
	child=rfork(RFPROC|RFFDG);
	if(child==0){
		close(launch[0]);
		snprint(name,sizeof name,"#d/%d",launch[1]);
		fd=open(name,OWRITE|OCEXEC);
		if(fd<0){ write(launch[1],"L",1); close(launch[1]); exits("launch channel"); }
		close(launch[1]);
		failure=dup(pipes[0][0],0)<0 || dup(pipes[1][1],1)<0 || dup(pipes[2][1],2)<0;
		closepipes(pipes,-1,-1);
		if(failure){ write(fd,"D",1); exits("dup"); }
		if(chdir(r->cwd)<0){ write(fd,"C",1); fprint(2,"p9cmdsrv: chdir %s: %r\n",r->cwd); exits("chdir"); }
		exec(r->args[0],r->args);
		write(fd,"E",1); fprint(2,"p9cmdsrv: exec %s: %r\n",r->args[0]); exits("exec");
	}
	close(launch[1]);
	closepipes(pipes,pipes[3][1],pipes[4][0]);
	if(child<0){
		put32(header,Startfailed); put32(header+4,21);
		writeall(pipes[3][1],header,8); writeall(pipes[3][1],"service: command fork",21);
		exits("command fork");
	}
	while((w=wait())!=nil && w->pid!=child) free(w);
	if(w==nil) exits("supervisor wait");
	failure=read(launch[0],&byte,1)>0; close(launch[0]);
	put32(header,failure ? Startfailed : 0); put32(header+4,strlen(w->msg));
	if(writeall(pipes[3][1],header,8)<0 || writeall(pipes[3][1],w->msg,strlen(w->msg))<0) exits("supervisor report");
	free(w); close(pipes[3][1]);
	/* Parent notes this group after capture, including surviving children
	 * in the same note group. Original rc background jobs can leave that
	 * group; only coordinator domain recovery stops all such descendants.
	 * Keep the group anchor even when rc itself exits first. */
	read(pipes[4][0],&byte,1); exits(nil); return -1;
}

static void
killjobs(int *pids)
{
	int i;
	if(pids[0]>0) postnote(PNGROUP,pids[0],"kill");
	for(i=0;i<4;i++) if(pids[i]>0) postnote(PNPROC,pids[i],"kill");
}

static int
helperstatus(char *status, char *word)
{
	int n, m;
	n=strlen(status); m=strlen(word);
	/* Original pexit prefixes nonempty status with program name and PID.
	 * This is used only after matching a service-owned helper PID. */
	return n>=m+2 && status[n-m-2]==':' && status[n-m-1]==' '
		&& strcmp(status+n-m,word)==0;
}

static int
cancelled(Request *r, char *directory)
{
	char expected[192], digest[65];
	uchar *marker;
	long bytes;
	int match;
	hex(r->digest,digest,32);
	snprint(expected,sizeof expected,"OC9CAN01 %s %s %s %s\n",generation,instance,r->id,digest);
	marker=readfile(directory,"cancel",sizeof expected,&bytes);
	if(marker==nil) return 0;
	match=bytes==strlen(expected) && memcmp(marker,expected,bytes)==0;
	free(marker); return match;
}

static void
execute(Request *r, char *directory, ulong *flagsp, char **statusp)
{
	int pipes[5][2], pids[5], i, j, remaining, pid, capturefailed, capturekilled;
	int delay;
	vlong deadline, left;
	ulong flags, length;
	uchar header[8], *decision;
	long decisionbytes;
	Waitmsg *w;
	char *status;
	memset(pids,0,sizeof pids); flags=0; status=nil; capturefailed=0; capturekilled=0;
	/* A bound cancellation already present at admission prevents launch.
	 * It still ends this instance, keeping one recovery rule for the caller. */
	if(cancelled(r,directory)){
		*flagsp=Cancelled; *statusp=strdup("service: command cancelled"); return;
	}
	for(i=0;i<5;i++){
		if(pipe(pipes[i])<0){
			for(j=0;j<i;j++){ close(pipes[j][0]); close(pipes[j][1]); }
			*flagsp=Startfailed; *statusp=strdup("service: pipe failed"); return;
		}
	}
	pids[0]=job(pipes,r);
	pids[1]=collector(pipes,1,directory,"stdout",r->outlimit);
	pids[2]=collector(pipes,2,directory,"stderr",r->errlimit);
	pids[3]=feeder(pipes,r);
	closepipes(pipes,pipes[3][0],pipes[4][1]);
	for(i=0;i<4;i++) if(pids[i]<0) flags|=Startfailed;
	if(flags) killjobs(pids);
	pids[4]=rfork(RFPROC|RFFDG);
	if(pids[4]==0){
		close(pipes[3][0]); close(pipes[4][1]);
		deadline=nsec()+(vlong)r->timeout*1000000;
		for(;;){
			/* Exact request-bound marker only. Cancel and deadline races are
			 * resolved by observation, not filesystem arrival timestamps.
			 * Native I/O can block; the coordinator still owns its watchdog. */
			if(cancelled(r,directory)){
				if(publish(directory,".interrupted","C",1)<0) exits("control record");
				killjobs(pids); exits("cancelled");
			}
			left=deadline-nsec();
			if(left<=0){
				if(publish(directory,".interrupted","T",1)<0) exits("control record");
				killjobs(pids); exits("timeout");
			}
			delay=left>=50000000 ? 50 : (left+999999)/1000000;
			sleep(delay);
		}
	}
	if(pids[4]<0){ flags|=Startfailed; killjobs(pids); }
	/* Collectors drain concurrently. The independent timer bounds this read,
	 * including a command that never exits or produces any output. */
	if(readn(pipes[3][0],header,8)==8){
		length=get32(header+4);
		if(length<=4096 && (get32(header)&~Startfailed)==0){
			status=malloc(length+1);
			if(status!=nil && readn(pipes[3][0],status,length)==length){
				status[length]=0; flags|=get32(header);
			}else{ free(status); status=nil; flags|=Startfailed; }
		}else flags|=Startfailed;
	}
	close(pipes[3][0]);
	remaining=0;
	for(i=0;i<5;i++) if(pids[i]>0) remaining++;
	while(remaining>0 && (w=wait())!=nil){
		pid=w->pid;
		for(i=0;i<5;i++) if(pids[i]==pid) break;
		if(i==5){ free(w); continue; }
		pids[i]=0; remaining--;
		if((i==1 || i==2) && helperstatus(w->msg,"truncated"))
			flags|=i==1 ? Outtruncated : Errtruncated;
		else if((i==1 || i==2) && helperstatus(w->msg,"kill")) capturekilled=1;
		else if((i==1 || i==2) && w->msg[0]!=0) capturefailed=1;
		if(i==4 && helperstatus(w->msg,"timeout")) flags|=Timedout;
		if(i==4 && helperstatus(w->msg,"cancelled")) flags|=Cancelled;
		if(i==4 && w->msg[0]!=0 && !helperstatus(w->msg,"timeout")
		&& !helperstatus(w->msg,"cancelled") && !helperstatus(w->msg,"kill"))
			fatal("command control failed; domain recovery required");
		free(w);
		if(pids[1]==0 && pids[2]==0 && pids[3]==0 && pids[0]>0)
			postnote(PNGROUP,pids[0],"kill");
		if(pids[0]==0 && pids[1]==0 && pids[2]==0 && pids[3]==0 && pids[4]>0)
			postnote(PNPROC,pids[4],"kill");
	}
	close(pipes[4][1]);
	/* The timer can be reaped after a collector or killed as the last helper.
	 * Commit its decision before sending notes, so that race cannot erase
	 * the interruption flag or permit another command after a partial kill. */
	if(present(directory,".interrupted")){
		decision=readfile(directory,".interrupted",1,&decisionbytes);
		if(decision==nil || decisionbytes!=1 || (decision[0]!='C' && decision[0]!='T'))
			fatal("command control incomplete; domain recovery required");
		flags|=decision[0]=='C' ? Cancelled : Timedout;
		free(decision);
	}
	if(capturefailed || (capturekilled && !(flags&Interrupted))) flags|=Startfailed;
	if(status==nil && !(flags&Interrupted)) flags|=Startfailed;
	if(remaining>0){ killjobs(pids); flags|=Startfailed; }
	if(status==nil) status=strdup(flags&Cancelled ? "service: command cancelled" :
		flags&Timedout ? "service: command timed out" : "service: execution did not produce status");
	*flagsp=flags; *statusp=status;
}

static void
complete(Request *r, char *directory)
{
	uchar *output, *error, *result;
	uchar outdigest[32], errdigest[32], resultdigest[32];
	char requesthex[65], resulthex[65], *done, *status, *reset;
	long outbytes, errbytes, resultbytes;
	ulong flags;
	execute(r,directory,&flags,&status);
	if(present(directory,".stdout.truncated")) flags|=Outtruncated;
	if(present(directory,".stderr.truncated")) flags|=Errtruncated;
	if(!present(directory,"stdout")) publish(directory,"stdout","",0);
	if(!present(directory,"stderr")) publish(directory,"stderr","",0);
	output=readfile(directory,"stdout",r->outlimit,&outbytes);
	error=readfile(directory,"stderr",r->errlimit,&errbytes);
	if(output==nil || error==nil) fatal("capture incomplete; request stays started");
	sha2_256(output,outbytes,outdigest,nil); sha2_256(error,errbytes,errdigest,nil);
	free(output); free(error);
	resultbytes=Resultheader+strlen(status); result=mallocz(resultbytes,1);
	if(result==nil) fatal("result allocation");
	memmove(result,"OC9RES01",8); memmove(result+8,generation,16);
	memmove(result+24,instance,32); memmove(result+56,r->id,32);
	memmove(result+88,r->digest,32);
	put32(result+120,flags); put32(result+124,outbytes); put32(result+128,errbytes);
	put32(result+132,strlen(status)); memmove(result+136,outdigest,32);
	memmove(result+168,errdigest,32); memmove(result+200,status,strlen(status));
	if(publish(directory,"status",status,strlen(status))<0
	|| publish(directory,"result",result,resultbytes)<0) fatal("result publication");
	sha2_256(result,resultbytes,resultdigest,nil);
	hex(r->digest,requesthex,32); hex(resultdigest,resulthex,32);
	if(flags&Interrupted){
		/* Original rc deliberately creates new note groups for background
		 * jobs. Userland group notes cannot prove complete descendant death.
		 * The owning coordinator must pause/recycle this Plan9 domain before
		 * exposing interrupted completion or launching another invocation.
		 * This marker reports recovery need; it grants no authority. */
		reset=smprint("OC9RESET1 %s %s %s %s %s\n",generation,instance,r->id,requesthex,resulthex);
		if(reset==nil || publish(servicedir,"reset-required",reset,strlen(reset))<0)
			fatal("interruption requires domain reset");
		free(reset);
	}
	done=smprint("OC9DONE1 %s %s %s %s %s\n",generation,instance,r->id,requesthex,resulthex);
	if(done==nil || publish(directory,"done",done,strlen(done))<0) fatal("completion publication");
	free(done); free(result); free(status);
	if(flags&Interrupted) exits("interruption requires domain reset");
}

static int
consider(char *name)
{
	Request request;
	char *directory, digest[65], *expected;
	uchar *commit;
	long commitbytes;
	Accepted *entry;
	int admitted;
	if(name[0]!='r' || !hexid(name+1,32)) return 0;
	directory=path(servicedir,name);
	for(entry=accepted; entry!=nil; entry=entry->next)
		if(strcmp(entry->id,name+1)==0){ free(directory); return 0; }
	if(!present(directory,"submit") || present(directory,"started")
	|| present(directory,"done") || present(directory,"rejected")){ free(directory); return 0; }
	admitted=0;
	memset(&request,0,sizeof request);
	request.wire=readfile(directory,"request",Maxrequest,&request.bytes);
	commit=readfile(directory,"submit",256,&commitbytes);
	if(request.wire==nil || commit==nil) goto Finished;
	sha2_256(request.wire,request.bytes,request.digest,nil); hex(request.digest,digest,32);
	expected=smprint("OC9SUB01 %s %s %s %s\n",generation,instance,name+1,digest);
	if(expected==nil) fatal("commit allocation");
	if(commitbytes!=strlen(expected) || memcmp(commit,expected,commitbytes)!=0){ free(expected); goto Finished; }
	free(expected);
	if(parse(&request,name+1)<0){
		publish(directory,"rejected","invalid request\n",16); goto Finished;
	}
	if(present(directory,"stdout") || present(directory,"stderr") || present(directory,"status")
	|| present(directory,"result")){
		publish(directory,"rejected","output already exists\n",22); goto Finished;
	}
	/* Complete publication precedes any execution. A crash after this point is
	 * an unknown completion, never permission to execute the request again. */
	entry=malloc(sizeof *entry);
	if(entry==nil) fatal("accepted request ledger allocation");
	memmove(entry->id,request.id,33); entry->next=accepted; accepted=entry;
	if(publish(directory,"started",commit,commitbytes)<0) fatal("start publication");
	admitted=1;
	complete(&request,directory);
Finished:
	free(commit); freerequest(&request); free(directory);
	return admitted;
}

static int
nextscan(int delay, int active)
{
	if(active) return Scanmin;
	if(delay>=Scanmax/2) return Scanmax;
	return delay*2;
}

static void
directory(char *p, int fresh)
{
	Dir *d;
	int fd;
	d=dirstat(p);
	if(d!=nil){
		if(fresh || !(d->mode&DMDIR)){ free(d); fatal("service instance/root already exists or is invalid"); }
		free(d); return;
	}
	fd=create(p,OREAD,DMDIR|0755);
	if(fd<0) fatal("service directory");
	close(fd);
}

void
main(int argc, char **argv)
{
	char *gdir, *ready;
	Dir *entries;
	int fd, n, i, delay, active;
	if(argc!=4 || argv[1][0]!='/' || !hexid(argv[2],16) || !hexid(argv[3],32)
	|| strcmp(argv[2],"0000000000000000")==0){
		fprint(2,"usage: p9cmdsrv /native/service/root generation16 instance32\n"); exits("usage");
	}
	memmove(generation,argv[2],17); memmove(instance,argv[3],33);
	directory(argv[1],0);
	gdir=smprint("%s/g%s",argv[1],generation);
	servicedir=smprint("%s/s%s",gdir,instance);
	if(gdir==nil || servicedir==nil) fatal("service allocation");
	directory(gdir,0); directory(servicedir,1); free(gdir);
	ready=smprint("OC9READY1 %s %s\n",generation,instance);
	if(ready==nil || publish(servicedir,"ready",ready,strlen(ready))<0) fatal("readiness publication");
	free(ready);
	/* Keep the directory fid open. Rewinding is local to the original mount
	 * client; the next Tread at offset zero enumerates the current namespace.
	 * Reopening each scan adds Twalk/Topen/Tclunk without making it fresher.
	 * No cached listing or directory-qid shortcut may hide a submit published
	 * inside a request directory that already existed at the previous scan. */
	fd=open(servicedir,OREAD|OCEXEC);
	if(fd<0) fatal("service scan");
	delay=Scanmin;
	for(;;){
		if(seek(fd,0,0)<0) fatal("service directory rewind");
		n=dirreadall(fd,&entries);
		if(n<0) fatal("service directory read");
		active=0;
		for(i=0;i<n;i++) if(entries[i].mode&DMDIR) active|=consider(entries[i].name);
		free(entries);
		/* Back off only between invocations, to a bounded 250ms admission
		 * interval. An admitted command resets the fast cadence immediately.
		 * execute's independent 50ms cancellation/deadline loop is unchanged. */
		if(active) delay=Scanmin;
		sleep(delay);
		delay=nextscan(delay,active);
	}
}
