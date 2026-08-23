//! Reproducibly wrap a wit-bindgen core module as a WebAssembly component.

use std::{env, error::Error, fs, path::PathBuf};

use wit_component::ComponentEncoder;

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os().skip(1).map(PathBuf::from);
    let input = args.next().ok_or("missing input core module path")?;
    let output = args.next().ok_or("missing output component path")?;
    if args.next().is_some() {
        return Err("expected exactly an input and output path".into());
    }

    let module = fs::read(&input)?;
    let component = ComponentEncoder::default()
        .module(&module)?
        .validate(true)
        .encode()?;
    fs::write(output, component)?;
    Ok(())
}
