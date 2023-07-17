#include "BuildInfo.h"
#include "binaryninjaapi.h"
#include "mediumlevelilinstruction.h"
#include <algorithm>
#include <map>
#include <chrono>
#include <thread>

using namespace BinaryNinja;

extern "C" {
BN_DECLARE_CORE_ABI_VERSION;

std::set<std::string> pac_instructions;

void DePacMLIL(Ref<AnalysisContext> analysisContext)
{
    Ref<Function> func = analysisContext->GetFunction();

    if (!func) {
        LogError("Could not get function object.");
    }

    if(func->IsAnalysisSkipped()) {
        const std::map<BNAnalysisSkipReason,const char*> skip_reasons {
            { NoSkipReason, "no reason" },
            { AlwaysSkipReason, "always skipped" },
            { ExceedFunctionSizeSkipReason, "exceeds 'analysis.limits.maxFunctionSize'" },
		    { ExceedFunctionAnalysisTimeSkipReason, "exceeds 'analysis.limits.maxFunctionAnalysisTime'" },
            { NewAutoFunctionAnalysisSuppressedReason, "Auto Function Analysis Suppression is enabled (analysis.suppressNewAutoFunctionAnalysis)" },
            { BasicAnalysisSkipReason, "basic analysis skipped" },
            { IntermediateAnalysisSkipReason, "intermediate analysis skipped" },
        };
        auto it  = skip_reasons.find(func->GetAnalysisSkipReason());
        const char* reason = it == skip_reasons.end() ? "invalid reason" : it->second;

        LogWarn("Analysis was skipped for function 0x%llx: %s", func->GetStart(), reason);
        return;
    }


    Ref<MediumLevelILFunction> mlil = analysisContext->GetMediumLevelILFunction();

    if (!mlil) {
        LogError("Could not get mlil function.");
        return;
    }

    Ref<Function> function = mlil->GetFunction();

    if (!function) {
        LogError("Could not get core function for mlil function at 0x%llx", mlil->GetCurrentAddress());
        return;
    }

    Ref<BinaryView> bv = analysisContext->GetFunction()->GetView();

    if (!bv) {
        LogError("Could not get binary view for mlil function at 0x%llx", mlil->GetCurrentAddress());
        return;
    }

    Ref<Architecture> arch = mlil->GetArchitecture();

    if (!arch) {
        LogError("Could not get arch for mlil function at 0x%llx", mlil->GetCurrentAddress());
        return;
    }

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

            LogDebug("0x%llx: Replacing intrinsic %s", insn.address, intrinsic.c_str());
            insn.Replace(mlil->SetVar(8, dest, src.CopyTo(mlil)));

            // Apply the type if possible.
            try {
                if (src.operation == MLIL_VAR) {
                    auto src_var = src.GetSourceVariable<MLIL_VAR>();
                    function->CreateAutoVariable(dest, function->GetVariableType(src_var), function->GetVariableName(src_var));
                }
            }
            catch(const std::exception &e) {
                LogError("0x%llx: Could not propagate type for instruction: %s", insn.address, e.what());
            }

            updated = true;
        }
    }

    if (updated)
        mlil->GenerateSSAForm();
}

bool WorkflowIsRegistered(const std::string& name) {
    std::vector<Ref<Workflow>> workflows = Workflow::GetList();
    auto it = std::find_if(workflows.begin(), workflows.end(), [name](Ref<Workflow> workflow) {
        return workflow->GetName() == name;
    });

    if (it == workflows.end()) {
        return false;
    }

    return true;
}

void RegisterWorkflow(const std::string& name, const std::string& parent, const std::string& before) {
    long long backoff = 10;
    while (!WorkflowIsRegistered(parent)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(backoff));
        backoff = backoff * 2;
        if (backoff > 10000) {
            LogError("Parent workflow %s not found", parent.c_str());
            return;
        }
    }

    Ref<Workflow> myWorkflow = Workflow::Instance(parent)->Clone(name);

    myWorkflow->RegisterActivity(
        new Activity("extension.depac", DePacMLIL));

    myWorkflow->Insert(before, "extension.depac");

    Workflow::RegisterWorkflow(myWorkflow,
        R"#({
            "title": "De-PAC Workflow",
            "description": "Removes PAC intrinsics",
            "capabilities": []
        })#");

        LogInfo("Registered Workflow: %s", name.c_str());
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

    std::thread register_default([]() {
        RegisterWorkflow(
            "extension.depac.defaultAnalysis",
            "core.function.defaultAnalysis",
            "core.function.analyzeTailCalls");
    });
    register_default.detach();

    std::thread register_objc([](){
        RegisterWorkflow(
            "extension.depac.objectiveC",
            "core.function.objectiveC",
            "core.function.analyzeTailCalls");
    });
    register_objc.detach();

    LogInfo("DePac loaded successfully (%s-%s/%s)",
        GitBranch, GitCommit, BuildType);

    return true;
}
}