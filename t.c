const int SbReadOnly = 100;
int sbReadWrite = 200;
int sBss;
extern void extFunc(void);

int func1(int arg)
{
	extFunc();
	return sBss+arg+SbReadOnly+sbReadWrite;
}

int func2(int arg)
{
	return arg-SbReadOnly+sbReadWrite;
}


