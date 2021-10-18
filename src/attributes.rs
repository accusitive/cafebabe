use std::borrow::Cow;
use std::ops::Deref;
use std::rc::Rc;

use crate::{read_u1, read_u2, read_u4, AccessFlags, ParseError, ParseOptions};
use crate::bytecode::{ByteCode};
use crate::constant_pool::{ConstantPoolEntry, NameAndType, LiteralConstant, MethodHandle, BootstrapArgument};
use crate::constant_pool::{read_cp_utf8, read_cp_utf8_opt, read_cp_classinfo, read_cp_classinfo_opt, read_cp_nameandtype_opt,
    read_cp_literalconstant, read_cp_integer, read_cp_float, read_cp_long, read_cp_double, read_cp_methodhandle,
    read_cp_bootstrap_argument, read_cp_moduleinfo, read_cp_packageinfo};
use crate::names::{is_field_descriptor, is_return_descriptor, is_unqualified_name};

#[derive(Debug)]
pub struct ExceptionTableEntry {
    pub start_pc: u16,
    pub end_pc: u16,
    pub handler_pc: u16,
    pub catch_type: Option<String>,
}

#[derive(Debug)]
pub struct CodeData {
    pub max_stack: u16,
    pub max_locals: u16,
    pub code: Vec<u8>,
    pub bytecode: Option<ByteCode>,
    pub exception_table: Vec<ExceptionTableEntry>,
    pub attributes: Vec<AttributeInfo>,
}

#[derive(Debug)]
pub enum VerificationType {
    Top,
    Integer,
    Float,
    Long,
    Double,
    Null,
    UninitializedThis,
    Uninitialized { code_offset: u16 },
    Object { class_name: String },
}

#[derive(Debug)]
pub enum StackMapEntry {
    Same { offset_delta: u16 },
    SameLocals1StackItem { offset_delta: u16, stack: VerificationType },
    Chop { offset_delta: u16, chop_count: u16 },
    Append { offset_delta: u16, locals: Vec<VerificationType> },
    FullFrame { offset_delta: u16, locals: Vec<VerificationType>, stack: Vec<VerificationType> },
}

bitflags! {
    pub struct InnerClassAccessFlags: u16 {
        const PUBLIC = AccessFlags::PUBLIC.bits();
        const PRIVATE = AccessFlags::PRIVATE.bits();
        const PROTECTED = AccessFlags::PROTECTED.bits();
        const STATIC = AccessFlags::STATIC.bits();
        const FINAL = AccessFlags::FINAL.bits();
        const INTERFACE = AccessFlags::INTERFACE.bits();
        const ABSTRACT = AccessFlags::ABSTRACT.bits();
        const SYNTHETIC = AccessFlags::SYNTHETIC.bits();
        const ANNOTATION = AccessFlags::ANNOTATION.bits();
        const ENUM = AccessFlags::ENUM.bits();
    }
}

#[derive(Debug)]
pub struct InnerClassEntry {
    pub inner_class_info: String,
    pub outer_class_info: Option<String>,
    pub inner_name: Option<String>,
    pub access_flags: InnerClassAccessFlags,
}

#[derive(Debug)]
pub struct LineNumberEntry {
    pub start_pc: u16,
    pub line_number: u16,
}

#[derive(Debug)]
pub struct LocalVariableEntry {
    pub start_pc: u16,
    pub length: u16,
    pub name: String,
    pub descriptor: String,
    pub index: u16,
}

#[derive(Debug)]
pub struct LocalVariableTypeEntry {
    pub start_pc: u16,
    pub length: u16,
    pub name: String,
    pub signature: String,
    pub index: u16,
}

#[derive(Debug)]
pub enum AnnotationElementValue {
    ByteConstant(i32),
    CharConstant(i32),
    DoubleConstant(f64),
    FloatConstant(f32),
    IntConstant(i32),
    LongConstant(i64),
    ShortConstant(i32),
    BooleanConstant(i32),
    StringConstant(String),
    EnumConstant { type_name: String, const_name: String },
    ClassLiteral { class_name: String },
    AnnotationValue(Annotation),
    ArrayValue(Vec<AnnotationElementValue>),
}

#[derive(Debug)]
pub struct AnnotationElement {
    pub name: String,
    pub value: AnnotationElementValue,
}

#[derive(Debug)]
pub struct Annotation {
    pub type_descriptor: String,
    pub elements: Vec<AnnotationElement>,
}

#[derive(Debug)]
pub struct ParameterAnnotation {
    pub annotations: Vec<Annotation>,
}

#[derive(Debug)]
pub struct TypeAnnotationLocalVarTargetEntry {
    pub start_pc: u16,
    pub length: u16,
    pub index: u16,
}

#[derive(Debug)]
pub enum TypeAnnotationTarget {
    TypeParameter { index: u8 },
    Supertype { index: u16 },
    TypeParameterBound { type_parameter_index: u8, bound_index: u8 },
    Empty,
    FormalParameter { index: u8 },
    Throws { index: u16 },
    LocalVar(Vec<TypeAnnotationLocalVarTargetEntry>),
    Catch { exception_table_index: u16 },
    Offset { offset: u16 },
    TypeArgument { offset: u16, type_argument_index: u8 },
}

#[derive(Debug)]
pub enum TypeAnnotationTargetPathKind {
    DeeperArray,
    DeeperNested,
    WildcardTypeArgument,
    TypeArgument,
}

#[derive(Debug)]
pub struct TypeAnnotationTargetPathEntry {
    pub path_kind: TypeAnnotationTargetPathKind,
    pub argument_index: u8,
}

#[derive(Debug)]
pub struct TypeAnnotation {
    pub target_type: TypeAnnotationTarget,
    pub target_path: Vec<TypeAnnotationTargetPathEntry>,
    pub annotation: Annotation,
}

#[derive(Debug)]
pub struct BootstrapMethodEntry {
    pub method: MethodHandle,
    pub arguments: Vec<BootstrapArgument>,
}

bitflags! {
    pub struct MethodParameterAccessFlags: u16 {
        const FINAL = AccessFlags::FINAL.bits();
        const SYNTHETIC = AccessFlags::SYNTHETIC.bits();
        const MANDATED = AccessFlags::MANDATED.bits();
    }
}

#[derive(Debug)]
pub struct MethodParameterEntry {
    pub name: Option<String>,
    pub access_flags: MethodParameterAccessFlags,
}

bitflags! {
    pub struct ModuleAccessFlags: u16 {
        const OPEN = AccessFlags::OPEN.bits();
        const SYNTHETIC = AccessFlags::SYNTHETIC.bits();
        const MANDATED = AccessFlags::MANDATED.bits();
    }
}

bitflags! {
    pub struct ModuleRequiresFlags: u16 {
        const TRANSITIVE = AccessFlags::TRANSITIVE.bits();
        const STATIC_PHASE = AccessFlags::STATIC_PHASE.bits();
        const SYNTHETIC = AccessFlags::SYNTHETIC.bits();
        const MANDATED = AccessFlags::MANDATED.bits();
    }
}

#[derive(Debug)]
pub struct ModuleRequireEntry {
    pub name: String,
    pub flags: ModuleRequiresFlags,
    pub version: Option<String>,
}

bitflags! {
    pub struct ModuleExportsFlags: u16 {
        const SYNTHETIC = AccessFlags::SYNTHETIC.bits();
        const MANDATED = AccessFlags::MANDATED.bits();
    }
}

#[derive(Debug)]
pub struct ModuleExportsEntry {
    pub package_name: String,
    pub flags: ModuleExportsFlags,
    pub exports_to: Vec<String>,
}

bitflags! {
    pub struct ModuleOpensFlags: u16 {
        const SYNTHETIC = AccessFlags::SYNTHETIC.bits();
        const MANDATED = AccessFlags::MANDATED.bits();
    }
}

#[derive(Debug)]
pub struct ModuleOpensEntry {
    pub package_name: String,
    pub flags: ModuleOpensFlags,
    pub opens_to: Vec<String>,
}

#[derive(Debug)]
pub struct ModuleProvidesEntry {
    pub service_interface_name: String,
    pub provides_with: Vec<String>,
}

#[derive(Debug)]
pub struct ModuleData {
    pub name: String,
    pub access_flags: ModuleAccessFlags,
    pub version: Option<String>,
    pub requires: Vec<ModuleRequireEntry>,
    pub exports: Vec<ModuleExportsEntry>,
    pub opens: Vec<ModuleOpensEntry>,
    pub uses: Vec<String>,
    pub provides: Vec<ModuleProvidesEntry>,
}

#[derive(Debug)]
pub struct RecordComponentEntry {
    pub name: String,
    pub descriptor: String,
    pub attributes: Vec<AttributeInfo>,
}

#[derive(Debug)]
pub enum AttributeData {
    ConstantValue(LiteralConstant),
    Code(CodeData),
    StackMapTable(Vec<StackMapEntry>),
    Exceptions(Vec<String>),
    InnerClasses(Vec<InnerClassEntry>),
    EnclosingMethod { class_name: String, method: Option<NameAndType> },
    Synthetic,
    Signature(String),
    SourceFile(String),
    SourceDebugExtension(String),
    LineNumberTable(Vec<LineNumberEntry>),
    LocalVariableTable(Vec<LocalVariableEntry>),
    LocalVariableTypeTable(Vec<LocalVariableTypeEntry>),
    Deprecated,
    RuntimeVisibleAnnotations(Vec<Annotation>),
    RuntimeInvisibleAnnotations(Vec<Annotation>),
    RuntimeVisibleParameterAnnotations(Vec<ParameterAnnotation>),
    RuntimeInvisibleParameterAnnotations(Vec<ParameterAnnotation>),
    RuntimeVisibleTypeAnnotations(Vec<TypeAnnotation>),
    RuntimeInvisibleTypeAnnotations(Vec<TypeAnnotation>),
    AnnotationDefault(AnnotationElementValue),
    BootstrapMethods(Vec<BootstrapMethodEntry>),
    MethodParameters(Vec<MethodParameterEntry>),
    Module(ModuleData),
    ModulePackages(Vec<String>),
    ModuleMainClass(String),
    NestHost(String),
    NestMembers(Vec<String>),
    Record(Vec<RecordComponentEntry>),
    Other(Vec<u8>),
}

#[derive(Debug)]
pub struct AttributeInfo {
    pub name: String,
    pub data: AttributeData,
}

fn ensure_length(length: usize, expected: usize) -> Result<(), ParseError> {
    if length != expected {
        fail!("Unexpected length {}", length);
    }
    Ok(())
}

fn read_code_data(bytes: &[u8], ix: &mut usize, pool: &[Rc<ConstantPoolEntry>], opts: &ParseOptions) -> Result<CodeData, ParseError> {
    let max_stack = read_u2(bytes, ix)?;
    let max_locals = read_u2(bytes, ix)?;
    let code_length = read_u4(bytes, ix)? as usize;
    if bytes.len() < *ix + code_length {
        fail!("Unexpected end of stream reading code attribute at index {}", *ix);
    }
    let code = &bytes[*ix .. *ix + code_length];
    *ix += code_length;
    let exception_table_count = read_u2(bytes, ix)?;
    let mut exception_table = Vec::with_capacity(exception_table_count.into());
    for i in 0..exception_table_count {
        let start_pc = read_u2(bytes, ix)?;
        let end_pc = read_u2(bytes, ix)?;
        let handler_pc = read_u2(bytes, ix)?;
        let catch_type = read_cp_classinfo_opt(bytes, ix, pool).map_err(|e| err!(e, "catch type of exception table entry {}", i))?;
        exception_table.push(ExceptionTableEntry {
            start_pc,
            end_pc,
            handler_pc,
            catch_type,
        });
    }
    let code_attributes = read_attributes(bytes, ix, pool, opts).map_err(|e| err!(e, "code attribute"))?;
    let bytecode = if opts.parse_bytecode {
        Some(ByteCode::from(code, pool).map_err(|e| err!(e, "bytecode"))?)
    } else {
        None
    };
    Ok(CodeData {
        max_stack,
        max_locals,
        code: code.to_vec(),
        bytecode,
        exception_table,
        attributes: code_attributes,
    })
}

fn read_stackmaptable_verification(bytes: &[u8], ix: &mut usize, pool: &[Rc<ConstantPoolEntry>]) -> Result<VerificationType, ParseError> {
    let verification_type = match read_u1(bytes, ix)? {
        0 => VerificationType::Top,
        1 => VerificationType::Integer,
        2 => VerificationType::Float,
        3 => VerificationType::Double,
        4 => VerificationType::Long,
        5 => VerificationType::Null,
        6 => VerificationType::UninitializedThis,
        7 => {
            let class_name = read_cp_classinfo(bytes, ix, pool).map_err(|e| err!(e, "object verification type"))?;
            VerificationType::Object { class_name }
        }
        8 => {
            let code_offset = read_u2(bytes, ix)?;
            VerificationType::Uninitialized { code_offset }
        }
        v => fail!("Unrecognized verification type {}", v),
    };
    Ok(verification_type)
}

fn read_stackmaptable_data(bytes: &[u8], ix: &mut usize, pool: &[Rc<ConstantPoolEntry>]) -> Result<Vec<StackMapEntry>, ParseError> {
    let count = read_u2(bytes, ix)?;
    let mut stackmapframes = Vec::with_capacity(count.into());
    for i in 0..count {
        let entry = match read_u1(bytes, ix)? {
            v @ 0..=63 => StackMapEntry::Same { offset_delta: v.into() },
            v @ 64..=127 => {
                let stack = read_stackmaptable_verification(bytes, ix, pool).map_err(|e| err!(e, "same_locals_1_stack_item_frame stack map entry {}", i))?;
                StackMapEntry::SameLocals1StackItem { offset_delta: (v - 64).into(), stack }
            }
            v @ 128..=246 => fail!(("Unrecognized discriminant {}", v), ("stack map entry {}", i)),
            247 => {
                let offset_delta = read_u2(bytes, ix)?;
                let stack = read_stackmaptable_verification(bytes, ix, pool).map_err(|e| err!(e, "same_locals_1_stack_item_frame_extended stack map entry {}", i))?;
                StackMapEntry::SameLocals1StackItem { offset_delta, stack }
            }
            v @ 248..=250 => {
                let offset_delta = read_u2(bytes, ix)?;
                StackMapEntry::Chop { offset_delta, chop_count: (251 - v).into() }
            }
            251 => {
                let offset_delta = read_u2(bytes, ix)?;
                StackMapEntry::Same { offset_delta }
            }
            v @ 252..=254 => {
                let offset_delta = read_u2(bytes, ix)?;
                let verification_count = v - 251;
                let mut locals = Vec::with_capacity(verification_count.into());
                for j in 0..verification_count {
                    locals.push(read_stackmaptable_verification(bytes, ix, pool).map_err(|e| err!(e, "local entry {} of append stack map entry {}", j, i))?);
                }
                StackMapEntry::Append { offset_delta, locals }
            }
            255 => {
                let offset_delta = read_u2(bytes, ix)?;
                let locals_count = read_u2(bytes, ix)?;
                let mut locals = Vec::with_capacity(locals_count.into());
                for j in 0..locals_count {
                    locals.push(read_stackmaptable_verification(bytes, ix, pool).map_err(|e| err!(e, "local entry {} of full-frame stack map entry {}", j, i))?);
                }
                let stack_count = read_u2(bytes, ix)?;
                let mut stack = Vec::with_capacity(stack_count.into());
                for j in 0..stack_count {
                    stack.push(read_stackmaptable_verification(bytes, ix, pool).map_err(|e| err!(e, "stack entry {} of full-frame stack map entry {}", j, i))?);
                }
                StackMapEntry::FullFrame { offset_delta, locals, stack }
            }
        };
        stackmapframes.push(entry);
    }
    Ok(stackmapframes)
}

fn read_exceptions_data(bytes: &[u8], ix: &mut usize, pool: &[Rc<ConstantPoolEntry>]) -> Result<Vec<String>, ParseError> {
    let count = read_u2(bytes, ix)?;
    let mut exceptions = Vec::with_capacity(count.into());
    for i in 0..count {
        let exception = read_cp_classinfo(bytes, ix, pool).map_err(|e| err!(e, "exception {}", i))?;
        exceptions.push(exception);
    }
    Ok(exceptions)
}

fn read_innerclasses_data(bytes: &[u8], ix: &mut usize, pool: &[Rc<ConstantPoolEntry>]) -> Result<Vec<InnerClassEntry>, ParseError> {
    let count = read_u2(bytes, ix)?;
    let mut innerclasses = Vec::with_capacity(count.into());
    for i in 0..count {
        let inner_class_info = read_cp_classinfo(bytes, ix, pool).map_err(|e| err!(e, "inner class info for inner class {}", i))?;
        let outer_class_info = read_cp_classinfo_opt(bytes, ix, pool).map_err(|e| err!(e, "outer class info for inner class {}", i))?;
        let inner_name = read_cp_utf8_opt(bytes, ix, pool).map_err(|e| err!(e, "inner name for inner class {}", i))?;
        let access_flags = InnerClassAccessFlags::from_bits_truncate(read_u2(bytes, ix)?);
        innerclasses.push(InnerClassEntry {
            inner_class_info,
            outer_class_info,
            inner_name,
            access_flags,
        });
    }
    Ok(innerclasses)
}

fn read_linenumber_data(bytes: &[u8], ix: &mut usize) -> Result<Vec<LineNumberEntry>, ParseError> {
    let count = read_u2(bytes, ix)?;
    let mut linenumbers = Vec::with_capacity(count.into());
    for _i in 0..count {
        let start_pc = read_u2(bytes, ix)?;
        let line_number = read_u2(bytes, ix)?;
        linenumbers.push(LineNumberEntry {
            start_pc,
            line_number,
        });
    }
    Ok(linenumbers)
}

fn read_localvariable_data(bytes: &[u8], ix: &mut usize, pool: &[Rc<ConstantPoolEntry>]) -> Result<Vec<LocalVariableEntry>, ParseError> {
    let count = read_u2(bytes, ix)?;
    let mut localvariables = Vec::with_capacity(count.into());
    for i in 0..count {
        let start_pc = read_u2(bytes, ix)?;
        let length = read_u2(bytes, ix)?;
        let name = read_cp_utf8(bytes, ix, pool).map_err(|e| err!(e, "name for variable {}", i))?;
        if !is_unqualified_name(&name, false, false) {
            fail!("Invalid unqualified name for variable {}", i);
        }
        let descriptor = read_cp_utf8(bytes, ix, pool).map_err(|e| err!(e, "descriptor for variable {}", i))?;
        if !is_field_descriptor(&descriptor) {
            fail!("Invalid descriptor for variable {}", i);
        }
        let index = read_u2(bytes, ix)?;
        localvariables.push(LocalVariableEntry {
            start_pc,
            length,
            name,
            descriptor,
            index,
        });
    }
    Ok(localvariables)
}

fn read_localvariabletype_data(bytes: &[u8], ix: &mut usize, pool: &[Rc<ConstantPoolEntry>]) -> Result<Vec<LocalVariableTypeEntry>, ParseError> {
    let count = read_u2(bytes, ix)?;
    let mut localvariabletypes = Vec::with_capacity(count.into());
    for i in 0..count {
        let start_pc = read_u2(bytes, ix)?;
        let length = read_u2(bytes, ix)?;
        let name = read_cp_utf8(bytes, ix, pool).map_err(|e| err!(e, "name for variable {}", i))?;
        if !is_unqualified_name(&name, false, false) {
            fail!("Invalid unqualified name for variable {}", i);
        }
        let signature = read_cp_utf8(bytes, ix, pool).map_err(|e| err!(e, "signature for variable {}", i))?;
        let index = read_u2(bytes, ix)?;
        localvariabletypes.push(LocalVariableTypeEntry {
            start_pc,
            length,
            name,
            signature,
            index,
        });
    }
    Ok(localvariabletypes)
}

fn read_annotation_element_value(bytes: &[u8], ix: &mut usize, pool: &[Rc<ConstantPoolEntry>]) -> Result<AnnotationElementValue, ParseError> {
    let value = match read_u1(bytes, ix)? as char {
        'B' => AnnotationElementValue::ByteConstant(read_cp_integer(bytes, ix, pool)?),
        'C' => AnnotationElementValue::CharConstant(read_cp_integer(bytes, ix, pool)?),
        'D' => AnnotationElementValue::DoubleConstant(read_cp_double(bytes, ix, pool)?),
        'F' => AnnotationElementValue::FloatConstant(read_cp_float(bytes, ix, pool)?),
        'I' => AnnotationElementValue::IntConstant(read_cp_integer(bytes, ix, pool)?),
        'J' => AnnotationElementValue::LongConstant(read_cp_long(bytes, ix, pool)?),
        'S' => AnnotationElementValue::ShortConstant(read_cp_integer(bytes, ix, pool)?),
        'Z' => AnnotationElementValue::BooleanConstant(read_cp_integer(bytes, ix, pool)?),
        's' => AnnotationElementValue::StringConstant(read_cp_utf8(bytes, ix, pool)?),
        'e' => {
            let type_name = read_cp_utf8(bytes, ix, pool)?;
            if !is_field_descriptor(&type_name) {
                fail!("Invalid enum descriptor");
            }
            let const_name = read_cp_utf8(bytes, ix, pool)?;
            AnnotationElementValue::EnumConstant { type_name, const_name }
        }
        'c' => {
            let class_name = read_cp_utf8(bytes, ix, pool)?;
            if !is_return_descriptor(&class_name) {
                fail!("Invalid classinfo descriptor");
            }
            AnnotationElementValue::ClassLiteral { class_name }
        }
        '@' => AnnotationElementValue::AnnotationValue(read_annotation(bytes, ix, pool)?),
        '[' => {
            let count = read_u2(bytes, ix)?;
            let mut array_values = Vec::with_capacity(count.into());
            for i in 0..count {
                array_values.push(read_annotation_element_value(bytes, ix, pool).map_err(|e| err!(e, "array index {}", i))?);
            }
            AnnotationElementValue::ArrayValue(array_values)
        }
        v => fail!("Unrecognized discriminant {}", v),
    };
    Ok(value)
}

fn read_annotation(bytes: &[u8], ix: &mut usize, pool: &[Rc<ConstantPoolEntry>]) -> Result<Annotation, ParseError> {
    let type_descriptor = read_cp_utf8(bytes, ix, pool).map_err(|e| err!(e, "type descriptor field"))?;
    if !is_field_descriptor(&type_descriptor) {
        fail!("Invalid descriptor");
    }
    let element_count = read_u2(bytes, ix)?;
    let mut elements = Vec::with_capacity(element_count.into());
    for i in 0..element_count {
        let name = read_cp_utf8(bytes, ix, pool).map_err(|e| err!(e, "name of element {}", i))?;
        let value = read_annotation_element_value(bytes, ix, pool).map_err(|e| err!(e, "value of element {}", i))?;
        elements.push(AnnotationElement {
            name,
            value,
        });
    }
    Ok(Annotation {
        type_descriptor,
        elements,
    })
}

fn read_annotation_data(bytes: &[u8], ix: &mut usize, pool: &[Rc<ConstantPoolEntry>]) -> Result<Vec<Annotation>, ParseError> {
    let count = read_u2(bytes, ix)?;
    let mut annotations = Vec::with_capacity(count.into());
    for i in 0..count {
        annotations.push(read_annotation(bytes, ix, pool).map_err(|e| err!(e, "annotation {}", i))?);
    }
    Ok(annotations)
}

fn read_parameter_annotation_data(bytes: &[u8], ix: &mut usize, pool: &[Rc<ConstantPoolEntry>]) -> Result<Vec<ParameterAnnotation>, ParseError> {
    let count = read_u1(bytes, ix)?;
    let mut parameters = Vec::with_capacity(count.into());
    for i in 0..count {
        let annotation_count = read_u2(bytes, ix)?;
        let mut annotations = Vec::with_capacity(annotation_count.into());
        for j in 0..annotation_count {
            annotations.push(read_annotation(bytes, ix, pool).map_err(|e| err!(e, "annotation {} of parameter {}", j, i))?);
        }
        parameters.push(ParameterAnnotation {
            annotations,
        });
    }
    Ok(parameters)
}

fn read_type_annotation_data(bytes: &[u8], ix: &mut usize, pool: &[Rc<ConstantPoolEntry>]) -> Result<Vec<TypeAnnotation>, ParseError> {
    let count = read_u2(bytes, ix)?;
    let mut annotations = Vec::with_capacity(count.into());
    for i in 0..count {
        let target_type = match read_u1(bytes, ix)? {
            0x00 | 0x01 => TypeAnnotationTarget::TypeParameter { index: read_u1(bytes, ix)? },
            0x10 => TypeAnnotationTarget::Supertype { index: read_u2(bytes, ix)? },
            0x11 | 0x12 => TypeAnnotationTarget::TypeParameterBound { type_parameter_index: read_u1(bytes, ix)?, bound_index: read_u1(bytes, ix)? },
            0x13 | 0x14 | 0x15 => TypeAnnotationTarget::Empty,
            0x16 => TypeAnnotationTarget::FormalParameter { index: read_u1(bytes, ix)? },
            0x17 => TypeAnnotationTarget::Throws { index: read_u2(bytes, ix)? },
            0x40 | 0x41 => {
                let localvar_count = read_u2(bytes, ix)?;
                let mut localvars = Vec::with_capacity(localvar_count.into());
                for _j in 0..localvar_count {
                    let start_pc = read_u2(bytes, ix)?;
                    let length = read_u2(bytes, ix)?;
                    let index = read_u2(bytes, ix)?;
                    localvars.push(TypeAnnotationLocalVarTargetEntry {
                        start_pc,
                        length,
                        index,
                    });
                }
                TypeAnnotationTarget::LocalVar(localvars)
            }
            0x42 => TypeAnnotationTarget::Catch { exception_table_index: read_u2(bytes, ix)? },
            0x43 | 0x44 | 0x45 | 0x46 => TypeAnnotationTarget::Offset { offset: read_u2(bytes, ix)? },
            0x47 | 0x48 | 0x49 | 0x4A | 0x4B => TypeAnnotationTarget::TypeArgument { offset: read_u2(bytes, ix)?, type_argument_index: read_u1(bytes, ix)? },
            v => fail!(("Unrecognized target type {}", v), ("type annotation {}", i)),
        };
        let path_count = read_u1(bytes, ix)?;
        let mut target_path = Vec::with_capacity(path_count.into());
        for j in 0..path_count {
            let path_kind = match read_u1(bytes, ix)? {
                0 => TypeAnnotationTargetPathKind::DeeperArray,
                1 => TypeAnnotationTargetPathKind::DeeperNested,
                2 => TypeAnnotationTargetPathKind::WildcardTypeArgument,
                3 => TypeAnnotationTargetPathKind::TypeArgument,
                v => fail!(("Unrecognized path kind {}", v), ("path element {} of type annotation {}", j, i)),
            };
            let argument_index = read_u1(bytes, ix)?;
            target_path.push(TypeAnnotationTargetPathEntry {
                path_kind,
                argument_index,
            });
        }
        let annotation = read_annotation(bytes, ix, pool).map_err(|e| err!(e, "type annotation {}", i))?;
        annotations.push(TypeAnnotation {
            target_type,
            target_path,
            annotation,
        });
    }
    Ok(annotations)
}

fn read_bootstrapmethods_data(bytes: &[u8], ix: &mut usize, pool: &[Rc<ConstantPoolEntry>]) -> Result<Vec<BootstrapMethodEntry>, ParseError> {
    let count = read_u2(bytes, ix)?;
    let mut bootstrapmethods = Vec::with_capacity(count.into());
    for i in 0..count {
        let method = read_cp_methodhandle(bytes, ix, pool).map_err(|e| err!(e, "method ref of bootstrap method {}", i))?;
        let arg_count = read_u2(bytes, ix)?;
        let mut arguments = Vec::with_capacity(arg_count.into());
        for j in 0..arg_count {
            let argument = read_cp_bootstrap_argument(bytes, ix, pool).map_err(|e| err!(e, "argument {} of bootstrap method {}", j, i))?;
            arguments.push(argument);
        }
        bootstrapmethods.push(BootstrapMethodEntry {
            method,
            arguments,
        });
    }
    Ok(bootstrapmethods)
}

fn read_methodparameters_data(bytes: &[u8], ix: &mut usize, pool: &[Rc<ConstantPoolEntry>]) -> Result<Vec<MethodParameterEntry>, ParseError> {
    let count = read_u1(bytes, ix)?;
    let mut methodparameters = Vec::with_capacity(count.into());
    for i in 0..count {
        let name = read_cp_utf8_opt(bytes, ix, pool).map_err(|e| err!(e, "name of method parameter {}", i))?;
        if name.is_some() && !is_unqualified_name(name.as_ref().unwrap(), false, false) {
            fail!("Invalid unqualified name for variable {}", i);
        }
        let access_flags = MethodParameterAccessFlags::from_bits(read_u2(bytes, ix)?).ok_or_else(|| err!(("Invalid access flags found"), ("method parameter {}", i)))?;
        methodparameters.push(MethodParameterEntry {
            name,
            access_flags,
        });
    }
    Ok(methodparameters)
}

fn read_module_data(bytes: &[u8], ix: &mut usize, pool: &[Rc<ConstantPoolEntry>]) -> Result<ModuleData, ParseError> {
    let name = read_cp_moduleinfo(bytes, ix, pool).map_err(|e| err!(e, "name"))?;
    let access_flags = ModuleAccessFlags::from_bits(read_u2(bytes, ix)?).ok_or_else(|| err!("Invalid access flags found"))?;
    let version = read_cp_utf8_opt(bytes, ix, pool).map_err(|e| err!(e, "version"))?;
    let requires_count = read_u2(bytes, ix)?;
    let mut requires = Vec::with_capacity(requires_count.into());
    for i in 0..requires_count {
        requires.push(ModuleRequireEntry {
            name: read_cp_moduleinfo(bytes, ix, pool).map_err(|e| err!(e, "name of requires entry {}", i))?,
            flags: ModuleRequiresFlags::from_bits(read_u2(bytes, ix)?).ok_or_else(|| err!(("Invalid module requires flags"), ("entry {}", i)))?,
            version: read_cp_utf8_opt(bytes, ix, pool).map_err(|e| err!(e, "version of requires entry {}", i))?,
        });
    }
    let exports_count = read_u2(bytes, ix)?;
    let mut exports = Vec::with_capacity(exports_count.into());
    for i in 0..exports_count {
        let package_name = read_cp_packageinfo(bytes, ix, pool).map_err(|e| err!(e, "package name of exports entry {}", i))?;
        let flags = ModuleExportsFlags::from_bits(read_u2(bytes, ix)?).ok_or_else(|| err!(("Invalid module exports flags"), ("entry {}", i)))?;
        let exports_to_count = read_u2(bytes, ix)?;
        let mut exports_to = Vec::with_capacity(exports_to_count.into());
        for j in 0..exports_to_count {
            exports_to.push(read_cp_moduleinfo(bytes, ix, pool).map_err(|e| err!(e, "name of exports_to entry {} of exports entry {}", j, i))?);
        }
        exports.push(ModuleExportsEntry {
            package_name,
            flags,
            exports_to,
        });
    }
    let opens_count = read_u2(bytes, ix)?;
    let mut opens = Vec::with_capacity(opens_count.into());
    for i in 0..opens_count {
        let package_name = read_cp_packageinfo(bytes, ix, pool).map_err(|e| err!(e, "package name of opens entry {}", i))?;
        let flags = ModuleOpensFlags::from_bits(read_u2(bytes, ix)?).ok_or_else(|| err!(("Invalid module opens flags"), ("entry {}", i)))?;
        let opens_to_count = read_u2(bytes, ix)?;
        let mut opens_to = Vec::with_capacity(opens_to_count.into());
        for j in 0..opens_to_count {
            opens_to.push(read_cp_moduleinfo(bytes, ix, pool).map_err(|e| err!(e, "name of opens_to entry {} of opens entry {}", j, i))?);
        }
        opens.push(ModuleOpensEntry {
            package_name,
            flags,
            opens_to,
        });
    }
    let uses_count = read_u2(bytes, ix)?;
    let mut uses = Vec::with_capacity(uses_count.into());
    for i in 0..uses_count {
        uses.push(read_cp_classinfo(bytes, ix, pool).map_err(|e| err!(e, "name of uses entry {}", i))?);
    }
    let provides_count = read_u2(bytes, ix)?;
    let mut provides = Vec::with_capacity(provides_count.into());
    for i in 0..provides_count {
        let service_interface_name = read_cp_classinfo(bytes, ix, pool).map_err(|e| err!(e, "service interface name of provides entry {}", i))?;
        let provides_with_count = read_u2(bytes, ix)?;
        let mut provides_with = Vec::with_capacity(provides_with_count.into());
        for j in 0..provides_with_count {
            provides_with.push(read_cp_classinfo(bytes, ix, pool).map_err(|e| err!(e, "provides_with entry {} of provides entry {}", j, i))?);
        }
        provides.push(ModuleProvidesEntry {
            service_interface_name,
            provides_with,
        });
    }
    Ok(ModuleData {
        name,
        access_flags,
        version,
        requires,
        exports,
        opens,
        uses,
        provides,
    })
}

fn read_modulepackages_data(bytes: &[u8], ix: &mut usize, pool: &[Rc<ConstantPoolEntry>]) -> Result<Vec<String>, ParseError> {
    let count = read_u2(bytes, ix)?;
    let mut packages = Vec::with_capacity(count.into());
    for i in 0..count {
        packages.push(read_cp_packageinfo(bytes, ix, pool).map_err(|e| err!(e, "package name {}", i))?);
    }
    Ok(packages)
}

fn read_nestmembers_data(bytes: &[u8], ix: &mut usize, pool: &[Rc<ConstantPoolEntry>]) -> Result<Vec<String>, ParseError> {
    let count = read_u2(bytes, ix)?;
    let mut members = Vec::with_capacity(count.into());
    for i in 0..count {
        members.push(read_cp_classinfo(bytes, ix, pool).map_err(|e| err!(e, "class name {}", i))?);
    }
    Ok(members)
}

fn read_record_data(bytes: &[u8], ix: &mut usize, pool: &[Rc<ConstantPoolEntry>], opts: &ParseOptions) -> Result<Vec<RecordComponentEntry>, ParseError> {
    let count = read_u2(bytes, ix)?;
    let mut components = Vec::with_capacity(count.into());
    for i in 0..count {
        let name = read_cp_utf8(bytes, ix, pool).map_err(|e| err!(e, "name of entry {}", i))?;
        if !is_unqualified_name(&name, false, false) {
            fail!("Invalid unqualified name for entry {}", i);
        }
        let descriptor = read_cp_utf8(bytes, ix, pool).map_err(|e| err!(e, "descriptor of entry {}", i))?;
        if !is_field_descriptor(&descriptor) {
            fail!("Invalid descriptor for entry {}", i);
        }
        let attributes = read_attributes(bytes, ix, pool, opts).map_err(|e| err!(e, "entry {}", i))?;
        components.push(RecordComponentEntry {
            name,
            descriptor,
            attributes,
        });
    }
    Ok(components)
}

pub(crate) fn read_attributes(bytes: &[u8], ix: &mut usize, pool: &[Rc<ConstantPoolEntry>], opts: &ParseOptions) -> Result<Vec<AttributeInfo>, ParseError> {
    let count = read_u2(bytes, ix)?;
    let mut attributes = Vec::with_capacity(count.into());
    for i in 0..count {
        let name = read_cp_utf8(bytes, ix, pool).map_err(|e| err!(e, "name field of attribute {}", i))?;
        let length = read_u4(bytes, ix)? as usize;
        let expected_end_ix = *ix + length;
        if bytes.len() < expected_end_ix {
            fail!("Unexpected end of stream reading attributes at index {}", *ix);
        }
        let data = match name.deref() {
            "ConstantValue" => {
                ensure_length(length, 2).map_err(|e| err!(e, "ConstantValue attribute {}", i))?;
                AttributeData::ConstantValue(read_cp_literalconstant(bytes, ix, pool).map_err(|e| err!(e, "value field of ConstantValue attribute {}", i))?)
            }
            "Code" => {
                let code_data = read_code_data(bytes, ix, pool, opts).map_err(|e| err!(e, "Code attribute {}", i))?;
                AttributeData::Code(code_data)
            }
            "StackMapTable" => {
                let stackmaptable_data = read_stackmaptable_data(bytes, ix, pool).map_err(|e| err!(e, "StackMapTable attribute {}", i))?;
                AttributeData::StackMapTable(stackmaptable_data)
            }
            "Exceptions" => {
                let exceptions_data = read_exceptions_data(bytes, ix, pool).map_err(|e| err!(e, "Exceptions attribute {}", i))?;
                AttributeData::Exceptions(exceptions_data)
            }
            "InnerClasses" => {
                let innerclasses_data = read_innerclasses_data(bytes, ix, pool).map_err(|e| err!(e, "InnerClasses attribute {}", i))?;
                AttributeData::InnerClasses(innerclasses_data)
            }
            "EnclosingMethod" => {
                ensure_length(length, 4).map_err(|e| err!(e, "EnclosingMethod attribute {}", i))?;
                let class_name = read_cp_classinfo(bytes, ix, pool).map_err(|e| err!(e, "class info of EnclosingMethod attribute {}", i))?;
                let method = read_cp_nameandtype_opt(bytes, ix, pool).map_err(|e| err!(e, "method info of EnclosingMethod attribute {}", i))?;
                AttributeData::EnclosingMethod { class_name, method }
            }
            "Synthetic" => {
                ensure_length(length, 0).map_err(|e| err!(e, "Synthetic attribute {}", i))?;
                AttributeData::Synthetic
            }
            "Signature" => {
                ensure_length(length, 2).map_err(|e| err!(e, "Signature attribute {}", i))?;
                // TODO: validate signature
                AttributeData::Signature(read_cp_utf8(bytes, ix, pool).map_err(|e| err!(e, "signature field of Signature attribute {}", i))?)
            }
            "SourceFile" => {
                ensure_length(length, 2).map_err(|e| err!(e, "SourceFile attribute {}", i))?;
                AttributeData::SourceFile(read_cp_utf8(bytes, ix, pool).map_err(|e| err!(e, "signature field of SourceFile attribute {}", i))?)
            }
            "SourceDebugExtension" => {
                let modified_utf8_data = &bytes[*ix .. *ix + length];
                *ix += length;
                let debug_str = cesu8::from_java_cesu8(modified_utf8_data).map_err(|e| err!(("{}", e), ("modified utf8 data of SourceDebugExtension attribute {}", i)))?;
                AttributeData::SourceDebugExtension(debug_str.to_string())
            }
            "LineNumberTable" => {
                let linenumber_data = read_linenumber_data(bytes, ix).map_err(|e| err!(e, "LineNumberTable attribute {}", i))?;
                AttributeData::LineNumberTable(linenumber_data)
            }
            "LocalVariableTable" => {
                let localvariable_data = read_localvariable_data(bytes, ix, pool).map_err(|e| err!(e, "LocalVariableTable attribute {}", i))?;
                AttributeData::LocalVariableTable(localvariable_data)
            }
            "LocalVariableTypeTable" => {
                let localvariabletype_data = read_localvariabletype_data(bytes, ix, pool).map_err(|e| err!(e, "LocalVariableTypeTable attribute {}", i))?;
                AttributeData::LocalVariableTypeTable(localvariabletype_data)
            }
            "Deprecated" => {
                ensure_length(length, 0).map_err(|e| err!(e, "Deprecated attribute {}", i))?;
                AttributeData::Deprecated
            }
            "RuntimeVisibleAnnotations" => {
                let annotation_data = read_annotation_data(bytes, ix, pool).map_err(|e| err!(e, "RuntimeVisibleAnnotations attribute {}", i))?;
                AttributeData::RuntimeVisibleAnnotations(annotation_data)
            }
            "RuntimeInvisibleAnnotations" => {
                let annotation_data = read_annotation_data(bytes, ix, pool).map_err(|e| err!(e, "RuntimeInvisibleAnnotations attribute {}", i))?;
                AttributeData::RuntimeInvisibleAnnotations(annotation_data)
            }
            "RuntimeVisibleParameterAnnotations" => {
                let annotation_data = read_parameter_annotation_data(bytes, ix, pool).map_err(|e| err!(e, "RuntimeVisibleParameterAnnotations attribute {}", i))?;
                AttributeData::RuntimeVisibleParameterAnnotations(annotation_data)
            }
            "RuntimeInvisibleParameterAnnotations" => {
                let annotation_data = read_parameter_annotation_data(bytes, ix, pool).map_err(|e| err!(e, "RuntimeInvisibleParameterAnnotations attribute {}", i))?;
                AttributeData::RuntimeInvisibleParameterAnnotations(annotation_data)
            }
            "RuntimeVisibleTypeAnnotations" => {
                let annotation_data = read_type_annotation_data(bytes, ix, pool).map_err(|e| err!(e, "RuntimeVisibleTypeAnnotations attribute {}", i))?;
                AttributeData::RuntimeVisibleTypeAnnotations(annotation_data)
            }
            "RuntimeInvisibleTypeAnnotations" => {
                let annotation_data = read_type_annotation_data(bytes, ix, pool).map_err(|e| err!(e, "RuntimeInvisibleTypeAnnotations attribute {}", i))?;
                AttributeData::RuntimeInvisibleTypeAnnotations(annotation_data)
            }
            "AnnotationDefault" => {
                let element_value = read_annotation_element_value(bytes, ix, pool).map_err(|e| err!(e, "AnnotationDefault attribute {}", i))?;
                AttributeData::AnnotationDefault(element_value)
            }
            "BootstrapMethods" => {
                let bootstrapmethods_data = read_bootstrapmethods_data(bytes, ix, pool).map_err(|e| err!(e, "BootstrapMethods attribute {}", i))?;
                AttributeData::BootstrapMethods(bootstrapmethods_data)
            }
            "MethodParameters" => {
                let methodparameters_data = read_methodparameters_data(bytes, ix, pool).map_err(|e| err!(e, "MethodParameters attribute {}", i))?;
                AttributeData::MethodParameters(methodparameters_data)
            }
            "Module" => {
                let module_data = read_module_data(bytes, ix, pool).map_err(|e| err!(e, "Module attribute {}", i))?;
                AttributeData::Module(module_data)
            }
            "ModulePackages" => {
                let modulepackages_data = read_modulepackages_data(bytes, ix, pool).map_err(|e| err!(e, "ModulePackages attribute {}", i))?;
                AttributeData::ModulePackages(modulepackages_data)
            }
            "ModuleMainClass" => {
                ensure_length(length, 2).map_err(|e| err!(e, "ModuleMainClass attribute {}", i))?;
                let main_class = read_cp_classinfo(bytes, ix, pool).map_err(|e| err!(e, "ModuleMainClass attribute {}", i))?;
                AttributeData::ModuleMainClass(main_class)
            }
            "NestHost" => {
                ensure_length(length, 2).map_err(|e| err!(e, "NestHost attribute {}", i))?;
                let host_class = read_cp_classinfo(bytes, ix, pool).map_err(|e| err!(e, "NestHost attribute {}", i))?;
                AttributeData::NestHost(host_class)
            }
            "NestMembers" => {
                let nestmembers_data = read_nestmembers_data(bytes, ix, pool).map_err(|e| err!(e, "NestMembers attribute {}", i))?;
                AttributeData::NestMembers(nestmembers_data)
            }
            "Record" => {
                let record_data = read_record_data(bytes, ix, pool, opts).map_err(|e| err!(e, "Record attribute {}", i))?;
                AttributeData::Record(record_data)
            }
            _ => {
                *ix += length;
                AttributeData::Other((&bytes[*ix - length .. *ix]).to_vec())
            }
        };
        if expected_end_ix != *ix {
            fail!("Length mismatch when reading attribute {}", i);
        }
        attributes.push(AttributeInfo {
            name,
            data,
        });
    }
    Ok(attributes)
}
