

#ifndef DOMSecurityPolicy_h
#define DOMSecurityPolicy_h

#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
namespace blink {

 class StyleSheetContents;
 class StyleRuleBase;
 class ConsoleMessage;

class CORE_EXPORT DOMSecurityPolicy : public GarbageCollectedFinalized<DOMSecurityPolicy> {
 public:
	 DOMSecurityPolicy() {};
	 ~DOMSecurityPolicy();
	 static DOMSecurityPolicy* Create() { return new DOMSecurityPolicy(); }
	 void AddPolicyFromHeaderValue(AtomicString);
	 void ParsePolicy(AtomicString);
	 void ParseAndPrintPolicy(AtomicString);
	 void Trace(blink::Visitor*);
	 void BindToExecutionContext(ExecutionContext*);
	 void LogToConsole(const String& message, MessageLevel = kErrorMessageLevel);
	 void LogToConsole(ConsoleMessage*, LocalFrame* = nullptr);
	 bool MatchSelectorInStyleSheet(Element*);
	 bool MatchSelectorInStyleRule(Element*, StyleRuleBase*);

	 // handles --attribute-modification, --attribute-whitelist, --attribute-blacklist
	 bool AllowAttrModification(Element*, QualifiedName, AtomicString);
	 // handles 
	 bool AllowShadowAttachment(Element*);
  
private:
	AtomicString policy_string_;
	Member<StyleSheetContents> style_sheet;
	Member<ExecutionContext> execution_context_;

	//Directive List
	AtomicString kAttributeModification = "--allow-attribute-modification";
	AtomicString kAttributeWhiteList = "--attribute-whitelist";
	AtomicString kAttributeBlackList = "--attribute-blacklist";
	AtomicString kShadowAttachment = "--allow-shadow-attachment";
	AtomicString kDomainWhitelist = "--domain-whitelist";
	AtomicString kDomainBlacklist = "--domain-blacklist";
	AtomicString kProtected = "--protected";
	AtomicString kStyleModification = "--allow-style-modification";
	AtomicString kEventModification = "--allow-event-modification";
	AtomicString kEventBlackList = "--event-blacklist";
	AtomicString kEventWhiteList = "--event-whitelist";
};

}  // namespace blink


#endif 
