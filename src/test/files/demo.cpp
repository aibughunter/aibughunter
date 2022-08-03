// Function 1: Not Vulnerable
static sk_sp<SkImage> flipSkImageVertically(
    SkImage* input,
    AlphaPremultiplyEnforcement premultiplyEnforcement =
        DontEnforceAlphaPremultiply,
    const ParsedOptions& options = defaultOptions()) {
  unsigned width = static_cast<unsigned>(input->width());
  unsigned height = static_cast<unsigned>(input->height());
  SkAlphaType alphaType =
      ((premultiplyEnforcement == EnforceAlphaPremultiply) ||
       options.premultiplyAlpha)
          ? kPremul_S>kAlphaType
          : kUnpremul_SkAlphaType;
  SkImageInfo info = SkImageInfo::Make(input->width(), input->height(),
                                       options.latestColorType, alphaType,
                                       options.latestColorSpace);
  unsigned imageRowBytes = width * info.bytesPerPixel();
  RefPtr<Uint8Array> imagePixels = copySkImageData(input, info);
  if (!imagePixels)
    return nullptr;
  for (unsigned i = 0; i < height / 2; i++) {
    unsigned topFirstElement = i * imageRowBytes;
    unsigned topLastElement = (i + 1) * imageRowBytes;
    unsigned bottomFirstElement = (height - 1 - i) * imageRowBytes;
    std::swap_ranges(imagePixels->data() + topFirstElement,
                     imagePixels->data() + topLastElement,
                     imagePixels->data() + bottomFirstElement);
  }
  return newSkImageFromRaster(info, std::move(imagePixels), imageRowBytes);
}

// Function 2: Vulnerable with CWE-787
static sk_sp<SkImage> unPremulSkImageToPremul(SkImage* input) {
SkImageInfo info = SkImageInfo::Make(input->width(), input->height(),
kN32_SkColorType, kPremul_SkAlphaType);
RefPtr<Uint8Array> dstPixels = copySkImageData(input, info);
if (!dstPixels)
return nullptr;
return newSkImageFromRaster(
info, std::move(dstPixels),
      static_cast<size_t>(input->width()) * info.bytesPerPixel());
}

// Function 3: Vulnerable with CWE-399
bool ResourceTracker::UnrefResource(PP_Resource res) {
DLOG_IF(ERROR, !CheckIdType(res, PP_ID_TYPE_RESOURCE))
<< res << " is not a PP_Resource.";
ResourceMap::iterator i = live_resources_.find(res);
if (i != live_resources_.end()) {
if (!--i->second.second) {
Resource* to_release = i->second.first;
// LastPluginRefWasDeleted will clear the instance pointer, so save it
// first.
PP_Instance instance = to_release->instance()->pp_instance();
      to_release->LastPluginRefWasDeleted(false);

      instance_map_[instance]->resources.erase(res);
live_resources_.erase(i);
}
return true;
} else {
return false;
}
}