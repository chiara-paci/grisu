import redis

class TestRunner(object):
    def __init__(self):
        self._tests={}

    def add_test(self,test,target):
        key=test.dest
        if key not in self._tests:
            self._tests[key]={
                "test": test,
                "targets": set()
            }

        self._tests[key]["targets"].add(target)

    def run(self):

        for desc in self._tests.values():
            t_command=desc["test"]
            target_list=list(desc["targets"])
            ret=t_command(target_list)

            if type(ret) is not list:
                print(t_command.txt(ret))
                continue

            for r in ret:
                print(t_command.txt(r))
            

            # for q,ok,out in ret:
            #     print(q)
            #     if ok:
            #         print("    OK",cmd_name)
            #         models.RemediationTestRun.objects.create(
            #             remediation=q,
            #             command=cmd_name,
            #             output=out
            #         )
            #         continue
            #     print("    NO",cmd_name)
            #     if type(out) is str:
            #         models.RemediationTestErrorRun.objects.create(
            #             remediation=q,
            #             command=cmd_name,
            #             error=out
            #         )
            #         continue
            #     models.RemediationTestErrorRun.objects.create(
            #         remediation=q,
            #         command=cmd_name,
            #         error=out.error,
            #         output=out.output,
            #         ret_code=out.ret_code
            #     )
