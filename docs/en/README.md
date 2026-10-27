# Network Mapping Server documentation

This is the English entry point for the server component. The first translated pages cover deployment and language support. Advanced topics currently remain in Chinese and are linked explicitly below.

- [Deployment and verification](DEPLOYMENT.md)
- [Language selection and documentation maintenance](LOCALIZATION.md)
- [Complete Chinese documentation](https://github.com/wshijiang/network-mapping/blob/main/docs/README.md)
- [Change log (Chinese)](https://github.com/wshijiang/network-mapping/blob/main/docs/CHANGELOG.md)
- [Source repository](https://github.com/wshijiang/network-mapping)

## Release preparation

This component is releasing **0.1.30**, paired with server **0.1.30**, scanner **0.1.21**, and web console **0.1.24**. The 2026-10-26 release was withdrawn and is being replaced on 2026-10-27 after fixes. Use the current tag commit, BUILD-INFO and SHA-256 files; do not reuse withdrawn artifacts. Existing installations must complete the transport endpoint migration before enabling new UDP tasks. Upgrade the Agent, Worker and complete module bundle together to IPC **3**, retaining node identity and pending results. See the [release and upgrade procedure (Chinese)](https://github.com/wshijiang/network-mapping/blob/main/docs/RELEASING.md) and the change log above for scope, rollback and tag checks after merging.

## Related components

- [Server documentation](https://github.com/wshijiang/network-mapping/blob/main/docs/README.md)
- [Web console documentation](https://github.com/wshijiang/network-mapping-vue/blob/main/docs/README.md)
- [Scanner documentation](https://github.com/wshijiang/Network-Mapping-Scanner/blob/main/docs/README.md)

The language menu switches to the translated counterpart when one exists. Otherwise it opens that language's documentation home. Translations do not change CLI options, API fields, protocol names or original evidence. Check the complete Chinese reference for features not covered here.
