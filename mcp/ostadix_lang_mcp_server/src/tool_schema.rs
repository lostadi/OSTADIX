//! Presentation compatibility for clients accepting a strict JSON Schema subset.
//! This retains the former tools/list adapter behavior without a transport proxy.

use serde_json::{json, Map, Value};

pub(crate) fn normalize(schema: &mut Map<String, Value>) {
    if schema.is_empty() {
        schema.insert("properties".into(), json!({}));
    }
    schema.remove("$schema");
    schema.remove("title");
    schema.entry("type").or_insert_with(|| json!("object"));
    if let Some(properties) = schema.get_mut("properties").and_then(Value::as_object_mut) {
        for property in properties.values_mut().filter_map(Value::as_object_mut) {
            if property.remove("nullable") == Some(Value::Bool(true)) {
                match property.get_mut("type") {
                    Some(value @ Value::String(_)) => *value = json!([value.clone(), "null"]),
                    Some(Value::Array(types)) if !types.contains(&json!("null")) => {
                        types.push(json!("null"))
                    }
                    _ => {}
                }
            }
            if property.get("format") == Some(&json!("uint64")) {
                property.remove("format");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_compatibility_preserves_validation_and_documentation() {
        let mut schema = json!({"$schema":"draft", "title":"Args", "required":["count"],
            "properties": {"count":{"type":"integer","format":"uint64","minimum":0,"description":"count"},
                "source":{"type":"string","nullable":true},"other":{"type":["string","null"],"nullable":true},
                "nested":{"type":"object","properties":{"title":{"type":"string"}}}},
            "additionalProperties":false}).as_object().unwrap().clone();
        normalize(&mut schema);
        assert_eq!(schema["type"], "object");
        assert!(!schema.contains_key("$schema"));
        assert!(!schema.contains_key("title"));
        assert_eq!(schema["required"], json!(["count"]));
        assert_eq!(
            schema["properties"]["count"],
            json!({"type":"integer","minimum":0,"description":"count"})
        );
        assert_eq!(
            schema["properties"]["source"],
            json!({"type":["string","null"]})
        );
        assert_eq!(
            schema["properties"]["other"],
            json!({"type":["string","null"]})
        );
        assert_eq!(
            schema["properties"]["nested"]["properties"]["title"]["type"],
            "string"
        );
        assert_eq!(schema["additionalProperties"], false);
        let once = schema.clone();
        normalize(&mut schema);
        assert_eq!(schema, once);
        let mut empty = Map::new();
        normalize(&mut empty);
        assert_eq!(
            Value::Object(empty),
            json!({"type":"object","properties":{}})
        );
    }
    #[test]
    fn every_advertised_tool_has_a_normalized_schema_and_retains_its_route() {
        let runtime =
            crate::RuntimeSearchPath::new(crate::RuntimePathMode::InheritedOnly, vec![]).unwrap();
        let server = crate::OstadixMcp::new(runtime);
        let original = crate::OstadixMcp::tool_router();
        assert_eq!(server.tool_router.map.len(), original.map.len());
        for tool in server.tool_router.list_all() {
            assert!(original.has_route(&tool.name));
            assert_eq!(tool.input_schema.get("type"), Some(&json!("object")));
            assert!(!tool.input_schema.contains_key("$schema"));
            assert!(!tool.input_schema.contains_key("title"));
            assert!(tool.input_schema["properties"].is_object());
            assert_eq!(tool.description, original.map[&tool.name].attr.description);
        }
    }
}
