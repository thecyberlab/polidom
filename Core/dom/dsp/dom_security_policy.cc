

#include "third_party/blink/renderer/core/dom/dsp/dom_security_policy.h"

#include "third_party/blink/renderer/core/css/css_custom_property_declaration.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/html/html_element.h"

namespace blink {
	
DOMSecurityPolicy::~DOMSecurityPolicy() = default;
void DOMSecurityPolicy::Trace(blink::Visitor* visitor) {
	visitor->Trace(style_sheet);
	visitor->Trace(execution_context_);
}
void DOMSecurityPolicy::AddPolicyFromHeaderValue(AtomicString policy_string) {
	policy_string_ = policy_string;
	LOG(INFO) << "I am in AddPolicyFromHeaderValue " << policy_string_;
	ParsePolicy(policy_string_);
}
void DOMSecurityPolicy::ParsePolicy(AtomicString policy_string) {
	CSSParserContext* context = CSSParserContext::Create(
		kHTMLStandardMode, SecureContextMode::kInsecureContext);
	style_sheet = StyleSheetContents::Create(context);
	style_sheet->ParseString(policy_string);
}
void DOMSecurityPolicy::BindToExecutionContext(ExecutionContext* execution_context) {
	execution_context_ = execution_context;
}
void DOMSecurityPolicy::LogToConsole(const String& message, MessageLevel level) {
	LogToConsole(ConsoleMessage::Create(kSecurityMessageSource, level, message));
}
void DOMSecurityPolicy::LogToConsole(ConsoleMessage* console_message, LocalFrame* frame) {
	if (execution_context_)
		execution_context_->AddConsoleMessage(console_message);
}
bool DOMSecurityPolicy::MatchSelectorInStyleSheet(Element* element) {
	for (unsigned i = 0; i < style_sheet->ChildRules().size(); ++i) {
		StyleRuleBase* rule = style_sheet->ChildRules()[i].Get();
			if (element->matches(AtomicString(ToStyleRule(rule)->SelectorList().SelectorsText())))
				return true;
	}
	return false;
}
bool DOMSecurityPolicy::MatchSelectorInStyleRule(Element* element, StyleRuleBase* rule) {
		if (element->matches(AtomicString(ToStyleRule(rule)->SelectorList().SelectorsText())))
			return true;
	return false;
}
bool DOMSecurityPolicy::AllowAttrModification(Element* element, QualifiedName name, AtomicString new_value) {
	for (unsigned i = 0; i < style_sheet->ChildRules().size(); ++i) {
		StyleRuleBase* rule = style_sheet->ChildRules()[i].Get();
		bool selectorMatched = MatchSelectorInStyleRule(element, rule);
		if (selectorMatched) {
			const CSSPropertyValueSet& property_set = ToStyleRule(rule)->Properties();

			// if attribute name is an event
			if (name.LocalName().StartsWith("on")) {
				// tripping the 'on' from event name so the 'onclick' becomes 'click'
				String eventName = name.LocalName().GetString();
				eventName.Replace("on", "");
				// for directive: --allow-event-modification
				if (property_set.FindPropertyIndex(kEventModification) != -1) {
					String allowEventModification = property_set.GetPropertyValue(kEventModification);
					if (allowEventModification.Replace(" ", "") == "false") {
						LogToConsole("The event modification request is blocked by DOM Security Policy!");
						return false;
					}
				}

				// for directive: --event-blacklist
				if (property_set.FindPropertyIndex(kEventBlackList) != -1) {
					String eventBlacklist = property_set.GetPropertyValue(kEventBlackList);
					if (eventBlacklist.Contains(eventName)) {
						LogToConsole("The event modification request is blocked by DOM Security Policy!");
						return false;
					}
				}

				// for directive: --event-whitelist
				if (property_set.FindPropertyIndex(kEventWhiteList) != -1) {
					String eventWhitelist = property_set.GetPropertyValue(kEventWhiteList);
					
					if (eventWhitelist.Contains(eventName))
						return true;
					else {
						LogToConsole("The event modification request is blocked by DOM Security Policy!");
						return false;
					}
				}
			}

			// for directive: --protected
			if (property_set.FindPropertyIndex(kProtected) != -1) {
				String Protected = property_set.GetPropertyValue(kProtected);
				if (Protected.Replace(" ", "") == "true") {
					LogToConsole("The attribute modification request is blocked by DOM Security Policy!");
					return false;
				}
			}

			// for directive: --allow-attribute-modification
			if (property_set.FindPropertyIndex(kAttributeModification) != -1) {
				String allowAttributeModification = property_set.GetPropertyValue(kAttributeModification);
				if (allowAttributeModification.Replace(" ", "") == "false") {
					LogToConsole("The attribute modification request is blocked by DOM Security Policy!");
					return false;
				}
			}

			// for directive: --attribute-blacklist
			if (property_set.FindPropertyIndex(kAttributeBlackList) != -1) {
				String attributeBlacklist = property_set.GetPropertyValue(kAttributeBlackList);
				if (attributeBlacklist.Contains(name.LocalName())) {
					LogToConsole("The attribute modification request is blocked by DOM Security Policy!");
					return false;
				}
			}

			// for directive: --attribute-whitelist
			if (property_set.FindPropertyIndex(kAttributeWhiteList) != -1) {
				String attributeWhitelist = property_set.GetPropertyValue(kAttributeWhiteList);
				if (attributeWhitelist.Contains(name.LocalName()))
					return true;
				else {
					LogToConsole("The attribute modification request is blocked by DOM Security Policy!");
					return false;
				}	
			}

			// for directive: --allow-style-modification
			if (property_set.FindPropertyIndex(kStyleModification) != -1) {
				String allowStyleModification = property_set.GetPropertyValue(kStyleModification);
				if (allowStyleModification.Replace(" ", "") == "false" && (name == HTMLNames::styleAttr || name == HTMLNames::classAttr)) {
					LogToConsole("The attribute modification request is blocked by DOM Security Policy!");
					return false;
				}
			}

			// for tags: img, iframe, object, a, script, video, source, audio, track
			if (((element->HasTagName(HTMLNames::imgTag) && name == HTMLNames::srcAttr))
				|| ((element->HasTagName(HTMLNames::iframeTag) && name == HTMLNames::srcAttr))
				|| ((element->HasTagName(HTMLNames::objectTag) && name == HTMLNames::dataAttr))
				|| ((element->HasTagName(HTMLNames::aTag) && name == HTMLNames::hrefAttr))
				|| ((element->HasTagName(HTMLNames::sourceTag) && (name == HTMLNames::srcAttr || name == HTMLNames::srcsetAttr)))
				|| ((element->HasTagName(HTMLNames::trackTag) && name == HTMLNames::srcAttr))
				|| ((element->HasTagName(HTMLNames::videoTag) && name == HTMLNames::srcAttr))
				|| ((element->HasTagName(HTMLNames::audioTag) && name == HTMLNames::srcAttr))
				|| ((element->HasTagName(HTMLNames::scriptTag) && name == HTMLNames::srcAttr))) {
				//LOG(INFO) << "i am image, iframe, object, script, or anchor tag ";

				// for directive: --domain-blacklist
				if (property_set.FindPropertyIndex(kDomainBlacklist) != -1) {
					String domainBlacklist = property_set.GetPropertyValue(kDomainBlacklist);
					if (domainBlacklist.Contains(AtomicString(KURL(new_value).Host()))) {
						LogToConsole("The attribute modification request is blocked by DOM Security Policy!");
						return false;
					}
				}

				// for directive: --domain-whitelist
				if (property_set.FindPropertyIndex(kDomainWhitelist) != -1) {
					String domainWhitelist = property_set.GetPropertyValue(kDomainWhitelist);
					if (domainWhitelist.Contains(AtomicString(KURL(new_value).Host())))
						return true;
					else {
						LogToConsole("The attribute modification request is blocked by DOM Security Policy!");
						return false;
					}
				}
			}
		}
	}
	return true;
}

bool DOMSecurityPolicy::AllowShadowAttachment(Element* element) {
	for (unsigned i = 0; i < style_sheet->ChildRules().size(); ++i) {
		StyleRuleBase* rule = style_sheet->ChildRules()[i].Get();
		bool selectorMatched = MatchSelectorInStyleRule(element, rule);
		if (selectorMatched) {
			const CSSPropertyValueSet& property_set = ToStyleRule(rule)->Properties();
			
			// for directive: --protected
			if (property_set.FindPropertyIndex(kProtected) != -1) {
				String Protected = property_set.GetPropertyValue(kProtected);
				if (Protected.Replace(" ", "") == "true") {
					LogToConsole("The shadow attachment request is blocked by DOM Security Policy!");
					return false;
				}
			}

			// for directive: --allow-shadow-attachment
			if (property_set.FindPropertyIndex(kShadowAttachment) != -1) {
				String allowShadowAttachment = property_set.GetPropertyValue(kShadowAttachment);
				if (allowShadowAttachment.Replace(" ", "") == "true")
					return true;
				else if (allowShadowAttachment.Replace(" ", "") == "false") {
					LogToConsole("The shadow attachment request is blocked by DOM Security Policy!");
					return false;
				}
			}
		}
	}
	LogToConsole("The shadow attachment request is blocked by DOM Security Policy!");
	return false;
}

void DOMSecurityPolicy::ParseAndPrintPolicy(AtomicString policy_string_)
{
	LOG(INFO) << "\n\nI am in ParseAndPrintPolicy: " << policy_string_ << "\n";
	LOG(INFO) << "Total ChildRules: " << style_sheet->ChildRules().size();
	for (unsigned i = 0; i < style_sheet->ChildRules().size(); ++i)
	{
		StyleRuleBase* rule = style_sheet->ChildRules()[i].Get();
		if (rule->IsStyleRule())
		{
			StyleRule* style_rule = ToStyleRule(rule);
			LOG(INFO) << "\nRule " << i << ": ";
			const CSSSelectorList& selector_list = style_rule->SelectorList();
			for (const CSSSelector* selector = selector_list.First(); selector; selector = selector_list.Next(*selector))
			{
				LOG(INFO) << "Selector Text: " << selector->SelectorText();
			}
			LOG(INFO) << "No of Properties: " << style_rule->Properties().PropertyCount();
			const CSSPropertyValueSet& property_set = style_rule->Properties();
			for (unsigned j = 0; j < property_set.PropertyCount(); j++)
			{
				CSSPropertyValueSet::PropertyReference property = property_set.PropertyAt(j);
				if (property.Id() == CSSPropertyVariable)
				{
					LOG(INFO) << "Name: " << ToCSSCustomPropertyDeclaration(property.Value()).GetName()
						<< ", Value: " << property.Value().CssText();
				}
			}
		}
	}
}  // namespace blink
