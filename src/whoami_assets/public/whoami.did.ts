import type { IDL } from "@dfinity/agent";

const WhoamiInterfaceFactory: IDL.InterfaceFactory = ({ IDL }) => {
  return IDL.Service({ 'whoami' : IDL.Func([], [IDL.Principal], []) });
};

export default WhoamiInterfaceFactory;
