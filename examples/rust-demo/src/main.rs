use smallvec::SmallVec;

fn main() {
    let mut values: SmallVec<[u8; 4]> = SmallVec::new();
    values.extend_from_slice(b"intake");
    println!("fixture for Software Intake Gatekeeper: {} bytes", values.len());
}
