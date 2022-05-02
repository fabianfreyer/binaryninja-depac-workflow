#include "BuildInfo.h"
#include "binaryninjaapi.h"
#include "mediumlevelilinstruction.h"
#include <algorithm>

using namespace BinaryNinja;

extern "C" {
BN_DECLARE_CORE_ABI_VERSION;

std::set<std::string> pac_instructions;

void DePacMLIL(Ref<AnalysisContext> analysisContext)
{
    Ref<MediumLevelILFunction> mlil = analysisContext->GetMediumLevelILFunction();

    if (!mlil)
        return;

    Ref<Function> function = mlil->GetFunction();

    if (!function)
        return;

    Ref<BinaryView> bv = analysisContext->GetFunction()->GetView();

    if (!bv)
        return;

    Ref<Architecture> arch = mlil->GetArchitecture();

    if (!arch)
        return;

    bool updated = false;

    // Loop over each instruction.
    for (auto& bb : mlil->GetBasicBlocks()) {
        for (size_t instrIndex = bb->GetStart(); instrIndex < bb->GetEnd(); instrIndex++) {
            auto insn = mlil->GetInstruction(instrIndex);
            if (insn.operation != MLIL_INTRINSIC)
                continue;

            std::string intrinsic = arch->GetIntrinsicName(insn.GetIntrinsic());

            if (pac_instructions.find(intrinsic) == pac_instructions.end())
                continue;

            auto outputs = insn.GetOutputVariables();
            if (outputs.size() < 1) {
                LogError("0x%llx: Intrinsic %s did not have enough outputs", insn.address, intrinsic.c_str());
                continue;
            }
            Variable dest = outputs[0];

            auto params = insn.GetParameterExprs();
            if (params.size() < 1) {
                LogError("0x%llx: Intrinsic %s did not have enough params", insn.address, intrinsic.c_str());
                continue;
            }
            auto src = params[0];

            LogInfo("0x%llx: Replacing intrinsic %s", insn.address, intrinsic.c_str());
            insn.Replace(mlil->SetVar(8, dest, src.CopyTo(mlil)));

            // Apply the type if possible.
            try {
                auto src_var = src.GetSourceVariable<MLIL_VAR>();
                function->CreateUserVariable(dest, function->GetVariableType(src_var), function->GetVariableName(src_var));
            }
            catch(...) {}

            updated = true;
        }
    }

    if (updated)
        mlil->GenerateSSAForm();
}

BINARYNINJAPLUGIN bool CorePluginInit()
{
    pac_instructions.insert("__pacia");
    pac_instructions.insert("__paciza");
    pac_instructions.insert("__pacia1718");
    pac_instructions.insert("__paciasp");
    pac_instructions.insert("__paciaz");
    pac_instructions.insert("__pacda");
    pac_instructions.insert("__pacdaz");
    pac_instructions.insert("__pacib");
    pac_instructions.insert("__pacizb");
    pac_instructions.insert("__pacib1718");
    pac_instructions.insert("__pacibsp");
    pac_instructions.insert("__pacibz");
    pac_instructions.insert("__pacdb");
    pac_instructions.insert("__pacdbz");
    pac_instructions.insert("__autia");
    pac_instructions.insert("__autiza");
    pac_instructions.insert("__autia1718");
    pac_instructions.insert("__autiasp");
    pac_instructions.insert("__autiaz");
    pac_instructions.insert("__autda");
    pac_instructions.insert("__autdza");
    pac_instructions.insert("__autib");
    pac_instructions.insert("__autizb");
    pac_instructions.insert("__autib1718");
    pac_instructions.insert("__autibsp");
    pac_instructions.insert("__autibz");
    pac_instructions.insert("__autdb");
    pac_instructions.insert("__autdzb");
    pac_instructions.insert("__xpaci");
    pac_instructions.insert("__xpacd");
    pac_instructions.insert("__xpaclri");

    Ref<Workflow> myWorkflow = Workflow::Instance()->Clone("DePacWorkflow");

    myWorkflow->RegisterActivity(
        new Activity("extension.DePacWorkflow", DePacMLIL));

    myWorkflow->Insert("core.function.analyzeTailCalls",
        "extension.DePacWorkflow");

    Workflow::RegisterWorkflow(myWorkflow,
        R"#({
			"title": "DePAC Workflow",
			"description": "Removes PAC intrinsics",
			"capabilities": []
		})#");

    LogInfo("DePac loaded successfully (%s-%s/%s)",
        GitBranch, GitCommit, BuildType);

    return true;
}
}